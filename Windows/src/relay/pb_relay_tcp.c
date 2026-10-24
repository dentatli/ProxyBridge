#include "pb_internal.h"

// Keep accepting while process/rule lookup and reporting run on one setup worker.
// This bounded queue owns accepted sockets until a connection worker takes over.
#define TCP_SETUP_QUEUE_CAPACITY 512

typedef struct {
    SOCKET socket;
    UINT16 source_port;
    BOOL is_ipv6;
    BOOL use_wfp_driver;
} TCP_ACCEPTED_CONNECTION;

typedef struct {
    SRWLOCK lock;
    HANDLE ready;
    HANDLE worker;
    volatile LONG stopping;
    unsigned int head, count;
    TCP_ACCEPTED_CONNECTION entries[TCP_SETUP_QUEUE_CAPACITY];
} TCP_SETUP_QUEUE;

static BOOL prepare_tcp_connection(const TCP_ACCEPTED_CONNECTION *accepted,
                                   CONNECTION_CONFIG *config)
{
    config->client_socket = accepted->socket;
    config->is_ipv6 = accepted->is_ipv6;
    config->action = RULE_ACTION_PROXY; // Legacy conntrack contains only proxied connections.
    if (!accepted->use_wfp_driver)
    {
        return accepted->is_ipv6
            ? get_connection_full_v6(accepted->source_port, FALSE, config->orig_dest_ip6,
                                     &config->orig_dest_port, &config->proxy_config_id)
            : get_connection_full(accepted->source_port, FALSE, &config->orig_dest_ip,
                                  &config->orig_dest_port, &config->proxy_config_id);
    }

    DWORD pid = 0;
    BOOL have_dest = accepted->is_ipv6
        ? pb_driver_orig_dest6(accepted->socket, config->orig_dest_ip6, &config->orig_dest_port, &pid)
        : pb_driver_orig_dest(accepted->socket, &config->orig_dest_ip, &config->orig_dest_port, &pid);
    if (!have_dest)
    {
        int error = WSAGetLastError();
        log_message("[RELAY] redirect-context query FAILED (WSA %d) - dropping", error);
        return FALSE;
    }

    char pname[MAX_PROCESS_NAME];
    UINT32 cfg = 0;
    RuleAction act = RULE_ACTION_PROXY;
    if (get_process_name_from_pid(pid, pname, sizeof(pname)))
        act = accepted->is_ipv6
            ? match_rule_v6(pname, config->orig_dest_ip6, config->orig_dest_port, FALSE, &cfg)
            : match_rule(pname, config->orig_dest_ip, config->orig_dest_port, FALSE, &cfg);
    config->proxy_config_id = cfg;
    config->action = act;
    if (!accepted->is_ipv6)
    {
        struct in_addr da; da.S_un.S_addr = config->orig_dest_ip;
        log_message("[RELAY] accepted redirect: pid=%lu dest=%s:%u action=%d cfg=%u",
                    pid, inet_ntoa(da), config->orig_dest_port, act, cfg);
    }
    pb_report_connection(pid, NULL, accepted->is_ipv6, config->orig_dest_ip,
                         accepted->is_ipv6 ? config->orig_dest_ip6 : NULL,
                         config->orig_dest_port, act, cfg, FALSE);
    return act != RULE_ACTION_BLOCK;
}

static DWORD WINAPI tcp_setup_worker(LPVOID arg)
{
    TCP_SETUP_QUEUE *queue = (TCP_SETUP_QUEUE *)arg;
    for (;;)
    {
        WaitForSingleObject(queue->ready, INFINITE);
        for (;;)
        {
            TCP_ACCEPTED_CONNECTION accepted;
            AcquireSRWLockExclusive(&queue->lock);
            if (queue->count == 0)
            {
                ReleaseSRWLockExclusive(&queue->lock);
                break;
            }
            accepted = queue->entries[queue->head];
            queue->head = (queue->head + 1) % TCP_SETUP_QUEUE_CAPACITY;
            --queue->count;
            ReleaseSRWLockExclusive(&queue->lock);

            if (InterlockedCompareExchange(&queue->stopping, 0, 0))
            {
                closesocket(accepted.socket);
                continue;
            }
            CONNECTION_CONFIG *config = (CONNECTION_CONFIG *)calloc(1, sizeof(*config));
            if (config != NULL && prepare_tcp_connection(&accepted, config) &&
                !InterlockedCompareExchange(&queue->stopping, 0, 0))
            {
                HANDLE worker = CreateThread(NULL, 1, connection_handler, config, 0, NULL);
                if (worker != NULL)
                {
                    CloseHandle(worker);
                    continue; // connection_handler owns config and socket now.
                }
            }
            closesocket(accepted.socket);
            free(config);
        }
        if (InterlockedCompareExchange(&queue->stopping, 0, 0)) return 0;
    }
}

static TCP_SETUP_QUEUE *start_tcp_setup_queue(void)
{
    TCP_SETUP_QUEUE *queue = (TCP_SETUP_QUEUE *)calloc(1, sizeof(*queue));
    if (queue == NULL) return NULL;
    InitializeSRWLock(&queue->lock);
    queue->ready = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (queue->ready != NULL)
    {
        queue->worker = CreateThread(NULL, 0, tcp_setup_worker, queue, 0, NULL);
        if (queue->worker != NULL) return queue;
        CloseHandle(queue->ready);
    }
    free(queue);
    return NULL;
}

static void queue_tcp_connection(TCP_SETUP_QUEUE *queue, SOCKET socket,
                                 BOOL is_ipv6, UINT16 source_port)
{
    BOOL queued = FALSE;
    AcquireSRWLockExclusive(&queue->lock);
    if (queue->count < TCP_SETUP_QUEUE_CAPACITY)
    {
        unsigned int tail = (queue->head + queue->count) % TCP_SETUP_QUEUE_CAPACITY;
        queue->entries[tail].socket = socket;
        queue->entries[tail].source_port = source_port;
        queue->entries[tail].is_ipv6 = is_ipv6;
        queue->entries[tail].use_wfp_driver = g_use_wfp_driver;
        ++queue->count;
        queued = TRUE;
    }
    ReleaseSRWLockExclusive(&queue->lock);
    if (queued) SetEvent(queue->ready);
    else closesocket(socket); // overload is bounded and never guesses a route.
}

static void stop_tcp_setup_queue(TCP_SETUP_QUEUE *queue)
{
    InterlockedExchange(&queue->stopping, 1);
    SetEvent(queue->ready);
    WaitForSingleObject(queue->worker, INFINITE);
    CloseHandle(queue->worker);
    CloseHandle(queue->ready);
    free(queue);
}


// TCP relay: accept loop, per-connection worker, and the two-way byte pump.

DWORD WINAPI local_proxy_server(LPVOID arg)
{
    WSADATA wsa_data;
    struct sockaddr_in addr;
    SOCKET listen_sock;
    int on = 1;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
    {
        log_message("WSAStartup failed (%lu)", GetLastError());
        return 1;
    }

    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock == INVALID_SOCKET)
    {
        log_message("Socket creation failed (%d)", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on));

    int nodelay = 1;
    setsockopt(listen_sock, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);  // ANY covers loopback: the WFP driver redirects
    addr.sin_port = htons(g_local_relay_port); // watched connections to 127.0.0.1:relay_port

    if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        log_message("Bind failed (%d)", WSAGetLastError());
        closesocket(listen_sock);
        WSACleanup();
        return 1;
    }

    if (listen(listen_sock, SOMAXCONN) == SOCKET_ERROR)
    {
        log_message("Listen failed (%d)", WSAGetLastError());
        closesocket(listen_sock);
        WSACleanup();
        return 1;
    }

    // IPv6 loopback listener for redirected IPv6 TCP
    SOCKET listen_sock6 = socket(AF_INET6, SOCK_STREAM, 0);
    if (listen_sock6 != INVALID_SOCKET)
    {
        int v6only = 1;
        setsockopt(listen_sock6, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&v6only, sizeof(v6only));
        setsockopt(listen_sock6, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on));
        setsockopt(listen_sock6, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));
        struct sockaddr_in6 addr6;
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_addr = in6addr_any;   // same reason as IPv4: accept on any local address
        addr6.sin6_port = htons(g_local_relay_port);
        if (bind(listen_sock6, (struct sockaddr*)&addr6, sizeof(addr6)) == SOCKET_ERROR ||
            listen(listen_sock6, SOMAXCONN) == SOCKET_ERROR)
        {
            log_message("IPv6 listen failed (%d)", WSAGetLastError());
            closesocket(listen_sock6);
            listen_sock6 = INVALID_SOCKET;
        }
        else
        {
            log_message("Local proxy IPv6 listening on [::]:%d", g_local_relay_port);
        }
    }

    TCP_SETUP_QUEUE *setup_queue = start_tcp_setup_queue();
    if (setup_queue == NULL)
    {
        closesocket(listen_sock);
        if (listen_sock6 != INVALID_SOCKET) closesocket(listen_sock6);
        WSACleanup();
        return 1;
    }

    log_message("Local proxy listening on port %d", g_local_relay_port);

    while (running)
    {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(listen_sock, &read_fds);
        if (listen_sock6 != INVALID_SOCKET)
            FD_SET(listen_sock6, &read_fds);
        struct timeval timeout = {1, 0};

        if (select(0, &read_fds, NULL, NULL, &timeout) <= 0)
            continue;

        if (FD_ISSET(listen_sock, &read_fds))
        {
            struct sockaddr_in client_addr;
            int addr_len = sizeof(client_addr);
            SOCKET client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &addr_len);

            if (client_sock != INVALID_SOCKET)
                queue_tcp_connection(setup_queue, client_sock, FALSE, ntohs(client_addr.sin_port));
        }

        if (listen_sock6 != INVALID_SOCKET && FD_ISSET(listen_sock6, &read_fds))
        {
            struct sockaddr_in6 client_addr6;
            int addr_len6 = sizeof(client_addr6);
            SOCKET client_sock6 = accept(listen_sock6, (struct sockaddr*)&client_addr6, &addr_len6);

            if (client_sock6 != INVALID_SOCKET)
                queue_tcp_connection(setup_queue, client_sock6, TRUE, ntohs(client_addr6.sin6_port));
        }
    }

    closesocket(listen_sock);
    if (listen_sock6 != INVALID_SOCKET) closesocket(listen_sock6);
    stop_tcp_setup_queue(setup_queue);
    WSACleanup();
    return 0;
}

DWORD WINAPI connection_handler(LPVOID arg)
{
    CONNECTION_CONFIG *config = (CONNECTION_CONFIG *)arg;
    SOCKET client_sock = config->client_socket;
    RuleAction action = config->action;
    UINT32 dest_ip = config->orig_dest_ip;
    UINT16 dest_port = config->orig_dest_port;
    UINT32 proxy_config_id = config->proxy_config_id;
    BOOL is_ipv6 = config->is_ipv6;
    UINT8 dest_ip6[16];
    if (is_ipv6) memcpy(dest_ip6, config->orig_dest_ip6, 16);
    SOCKET socks_sock;
    struct sockaddr_in socks_addr;

    free(config);

    // DIRECT is an explicit route, independent of proxy configuration or availability.
    if (action == RULE_ACTION_DIRECT)
    {
        struct sockaddr_storage destination;
        int destination_size;
        memset(&destination, 0, sizeof(destination));
        if (is_ipv6)
        {
            struct sockaddr_in6 *address = (struct sockaddr_in6 *)&destination;
            address->sin6_family = AF_INET6;
            address->sin6_port = htons(dest_port);
            memcpy(&address->sin6_addr, dest_ip6, 16);
            destination_size = sizeof(*address);
        }
        else
        {
            struct sockaddr_in *address = (struct sockaddr_in *)&destination;
            address->sin_family = AF_INET;
            address->sin_port = htons(dest_port);
            address->sin_addr.s_addr = dest_ip;
            destination_size = sizeof(*address);
        }
        socks_sock = socket(is_ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (socks_sock == INVALID_SOCKET)
        {
            closesocket(client_sock);
            return 1;
        }
        configure_tcp_socket(socks_sock, 4194304, 30000);
        configure_tcp_socket(client_sock, 4194304, 30000);
        if (connect_with_timeout(socks_sock, (struct sockaddr *)&destination,
                                 destination_size, 30000) == SOCKET_ERROR)
        {
            log_message("[RELAY] DIRECT connection failed - dropping without proxy fallback");
            closesocket(socks_sock);
            closesocket(client_sock);
            return 1;
        }
        goto relay_connected;
    }
    if (action != RULE_ACTION_PROXY)
    {
        closesocket(client_sock);
        return 1;
    }

    // Snapshot the proxy config so this thread is immune to a concurrent Edit/Delete while it
    // uses the settings across the (blocking) SOCKS5/HTTP handshake below.
    PROXY_CONFIG proxy_snapshot;
    PROXY_CONFIG *proxy = &proxy_snapshot;
    if (!find_proxy_config_copy(proxy_config_id, &proxy_snapshot) ||
        proxy->host[0] == '\0' || proxy->port == 0)
    {
        log_message("[RELAY] No proxy config (id=%u) - dropping connection", proxy_config_id);
        closesocket(client_sock);
        return 1;
    }

    // Connect to proxy, use cached resolved IP to avoid DNS per connection
    UINT32 proxy_ip = proxy->resolved_ip ? proxy->resolved_ip : resolve_hostname(proxy->host);
    if (proxy_ip == 0)
    {
        closesocket(client_sock);
        return 1;
    }

    socks_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (socks_sock == INVALID_SOCKET)
    {
        log_message("Socket creation failed (%d)", WSAGetLastError());
        closesocket(client_sock);
        return 0;
    }

    // 4 MB kernel socket buffers for the relay sockets.
    // The upload path writes from client→proxy over a real network with non-zero
    // RTT; a small (512 KB) send buffer causes send_all() to block the moment
    // the proxy's receive window fills up, which stalls the relay loop and
    // triggers TCP flow-control on the client side → massive upload throughput
    // loss.  4 MB gives plenty of headroom even at high bitrates / high RTT.
    configure_tcp_socket(socks_sock, 4194304, 30000);  // 4 MB – proxy connection
    configure_tcp_socket(client_sock, 4194304, 30000); // 4 MB – app connection

    memset(&socks_addr, 0, sizeof(socks_addr));
    socks_addr.sin_family = AF_INET;
    socks_addr.sin_addr.s_addr = proxy_ip;
    socks_addr.sin_port = htons(proxy->port);

    if (connect(socks_sock, (struct sockaddr *)&socks_addr, sizeof(socks_addr)) == SOCKET_ERROR)
    {
        log_message("[RELAY] Failed to connect to proxy %s:%d (%d)", proxy->host, proxy->port, WSAGetLastError());
        closesocket(client_sock);
        closesocket(socks_sock);
        return 0;
    }

    if (proxy->type == PROXY_TYPE_SOCKS5)
    {
        int rc;
        char cached_domain[256];
        // Per-config: only hand the hostname to the proxy (socks5h) when this config
        // opts in; otherwise send the locally-resolved IP (socks5).
        if (is_ipv6)
        {
            if (proxy->send_domain_to_proxy && dns_cache_lookup_v6(dest_ip6, cached_domain, sizeof(cached_domain)))
                rc = socks5_connect_domain(socks_sock, cached_domain, dest_port, proxy);
            else
                rc = socks5_connect_v6(socks_sock, dest_ip6, dest_port, proxy);
        }
        else
        {
            if (proxy->send_domain_to_proxy && dns_cache_lookup(dest_ip, cached_domain, sizeof(cached_domain)))
                rc = socks5_connect_domain(socks_sock, cached_domain, dest_port, proxy);
            else
                rc = socks5_connect(socks_sock, dest_ip, dest_port, proxy);
        }
        if (rc != 0)
        {
            closesocket(client_sock);
            closesocket(socks_sock);
            return 0;
        }
    }
    else if (proxy->type == PROXY_TYPE_HTTP)
    {
        int rc = is_ipv6
            ? http_connect_v6(socks_sock, dest_ip6, dest_port, proxy)
            : http_connect(socks_sock, dest_ip, dest_port, proxy);
        if (rc != 0)
        {
            closesocket(client_sock);
            closesocket(socks_sock);
            return 0;
        }
    }

relay_connected:;
    // Disable timeout for data transfer phase
    DWORD zero_timeout = 0;
    setsockopt(socks_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&zero_timeout, sizeof(zero_timeout));
    setsockopt(socks_sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&zero_timeout, sizeof(zero_timeout));
    setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&zero_timeout, sizeof(zero_timeout));
    setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&zero_timeout, sizeof(zero_timeout));

    // Enable and configure customized TCP keep-alives
    struct tcp_keepalive keepalive_settings;
    keepalive_settings.onoff = 1;
    keepalive_settings.keepalivetime = 300000;      // 5 minutes in milliseconds
    keepalive_settings.keepaliveinterval = 1000;    // 1 second interval
    DWORD bytes_returned = 0;
    WSAIoctl(socks_sock, SIO_KEEPALIVE_VALS, &keepalive_settings, sizeof(keepalive_settings), NULL, 0, &bytes_returned, NULL, NULL);
    WSAIoctl(client_sock, SIO_KEEPALIVE_VALS, &keepalive_settings, sizeof(keepalive_settings), NULL, 0, &bytes_returned, NULL, NULL);

    TRANSFER_CONFIG *transfer_config = (TRANSFER_CONFIG *)malloc(sizeof(TRANSFER_CONFIG));

    if (transfer_config == NULL)
    {
        log_message("Memory allocation failed for transfer_config");
        closesocket(client_sock);
        closesocket(socks_sock);
        return 0;
    }

    transfer_config->from_socket = client_sock;
    transfer_config->to_socket = socks_sock;

    // both transfer in current thread
    transfer_handler((LPVOID)transfer_config);

    // Sockets already closed in transfer_handler!

    return 0;
}

// One-directional relay: reads from `from` and writes to `to`.
// Runs as a dedicated thread so upload and download never block each other.
// Uses a shared RELAY_PAIR reference count for safe socket cleanup:
//   - whichever direction finishes first calls shutdown() on both sockets,
//     which causes the sibling thread's recv() to return 0 and exit cleanly.
//   - the last thread to exit (refs drops to 0) closes both sockets and
//     frees the shared RELAY_PAIR.
DWORD WINAPI one_way_relay(LPVOID arg)
{
    ONE_WAY_CONFIG *cfg = (ONE_WAY_CONFIG *)arg;
    RELAY_PAIR *pair = cfg->pair;
    SOCKET from = cfg->from;
    SOCKET to   = cfg->to;
    free(cfg);

    char *buf = (char *)malloc(131072);  // 128 KB per-direction buffer
    if (buf)
    {
        int len;
        while ((len = recv(from, buf, 131072, 0)) > 0)
        {
            if (send_all(to, buf, len) == SOCKET_ERROR)
                break;
        }
        free(buf);
    }

    // Signal the sibling relay to stop by shutting down both sockets.
    // shutdown() is safe to call from any thread; it just drains/resets the
    // socket without closing the handle, so the other thread's recv() returns 0.
    shutdown(pair->sock_client, SD_BOTH);
    shutdown(pair->sock_proxy,  SD_BOTH);

    // Last thread out closes and frees everything.
    if (InterlockedDecrement(&pair->refs) == 0)
    {
        closesocket(pair->sock_client);
        closesocket(pair->sock_proxy);
        free(pair);
    }

    return 0;
}

// Bidirectional relay: spawns one thread for upload (client→proxy) and runs
// the download (proxy→client) direction in the calling thread.  Blocks until
// both directions have finished so the caller (connection_handler) can return
// cleanly and its thread handle can be closed.
DWORD WINAPI transfer_handler(LPVOID arg)
{
    TRANSFER_CONFIG *config = (TRANSFER_CONFIG *)arg;
    SOCKET sock_client = config->from_socket;
    SOCKET sock_proxy  = config->to_socket;
    free(config);

    RELAY_PAIR *pair = (RELAY_PAIR *)malloc(sizeof(RELAY_PAIR));
    if (!pair)
    {
        closesocket(sock_client);
        closesocket(sock_proxy);
        return 1;
    }
    pair->sock_client = sock_client;
    pair->sock_proxy  = sock_proxy;
    pair->refs        = 2;

    // Upload: client → proxy  (dedicated thread - may block on slow proxy send)
    ONE_WAY_CONFIG *up = (ONE_WAY_CONFIG *)malloc(sizeof(ONE_WAY_CONFIG));
    // Download: proxy → client (runs in this thread - loopback, rarely blocks)
    ONE_WAY_CONFIG *dn = (ONE_WAY_CONFIG *)malloc(sizeof(ONE_WAY_CONFIG));

    if (!up || !dn)
    {
        free(up);
        free(dn);
        free(pair);
        closesocket(sock_client);
        closesocket(sock_proxy);
        return 1;
    }

    up->pair = pair;  up->from = sock_client;  up->to = sock_proxy;
    dn->pair = pair;  dn->from = sock_proxy;   dn->to = sock_client;

    // Spawn the upload relay in its own thread.
    HANDLE upload_thread = CreateThread(NULL, 0, one_way_relay, up, 0, NULL);
    if (!upload_thread)
    {
        free(up);
        free(dn);
        free(pair);
        closesocket(sock_client);
        closesocket(sock_proxy);
        return 1;
    }

    // Run the download relay in this thread (blocks until done).
    one_way_relay(dn);

    // Wait for the upload relay thread to finish, then clean up its handle.
    WaitForSingleObject(upload_thread, INFINITE);
    CloseHandle(upload_thread);

    return 0;
}
