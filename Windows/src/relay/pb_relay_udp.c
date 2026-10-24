// One IOCP owns every UDP association and all packet I/O. SOCKS handshakes
// never block traffic belonging to an established association.
#include "pb_internal.h"
#include "ProxyBridgeDrv_user.h"
#include <mswsock.h>
#include <stddef.h>

#define SESSION_LIMIT 512u
#define ROUTE_LIMIT 128u
#define PENDING_LIMIT (2u * 1024u * 1024u)
#define SESSION_PENDING_LIMIT (128u * 1024u)
#define IDLE_MS 300000u
#define HANDSHAKE_MS 5000u

typedef struct SESSION SESSION;
typedef struct IO {
    OVERLAPPED ov;
    SESSION *session;
    int kind, stage;
    DWORD size, used, capacity;
    PADDRINFOEXW addresses;
    HANDLE resolver;
    ADDRINFOEXW hints;
    struct timeval timeout;
    DWORD dnsError;
    UINT16 dnsPort;
    UINT8 data[1];
} IO;
typedef struct ROUTE {
    struct ROUTE *next;
    PBDRV_UDP_RECORD record;
    ULONGLONG used;
} ROUTE;
typedef struct PENDING {
    struct PENDING *next;
    PBDRV_UDP_RECORD record;
} PENDING;
struct SESSION {
    SESSION *next;
    SESSION *hashNext;
    UINT64 endpoint;
    UINT32 configId;
    UINT32 compartment, bucket;
    UINT16 localFamily, localPort;
    UINT8 localAddress[16];
    PROXY_CONFIG config;
    SOCKET tcp, udp;
    LONG refs;
    BOOL closing, ready;
    ULONGLONG created, active;
    int replyType;
    ROUTE *routes;
    unsigned routeCount, pendingBytes;
    PENDING *first, *last;
    IO *dns;
};
typedef struct NAME {
    struct NAME *next;
    struct NAME *hashNext;
    UINT64 endpoint;
    char process[MAX_PROCESS_NAME];
    ULONGLONG active;
} NAME;
enum { DRIVER_READ, DRIVER_WRITE, CONNECT, TCP_SEND, TCP_READ, UDP_READ, UDP_SEND, RESOLVE };
enum { GREETING, AUTHENTICATED, REPLY_HEADER, REPLY_LENGTH, REPLY_ADDRESS, CONTROL };
static HANDLE gPort, gDriver = INVALID_HANDLE_VALUE, gThread;
static volatile LONG gStop;
static SESSION *gSessions;
static SESSION *gSessionBuckets[256];
static NAME *gNames;
static NAME *gNameBuckets[256];
static unsigned gSessionCount, gNameCount, gPendingBytes, gIoCount;
static unsigned gIoBytes;
static ULONGLONG gLastSweep;
static UINT64 gDrops, gMalformed, gIoErrors;

static UINT32 SessionBucket(const PBDRV_UDP_RECORD *r, UINT32 config)
{
    UINT32 hash=(UINT32)r->endpointId ^ (UINT32)(r->endpointId>>32) ^ config ^ r->compartment ^ r->family;
    for(unsigned n=0;n<16;++n) hash=(hash*33)^r->localAddress[n];
    return hash%ARRAYSIZE(gSessionBuckets);
}

static void CloseSession(SESSION *s);
static unsigned NameBucket(UINT64 endpoint) { return (unsigned)(endpoint^(endpoint>>32))%ARRAYSIZE(gNameBuckets); }
static void FreeName(NAME *name)
{
    NAME **bucket=&gNameBuckets[NameBucket(name->endpoint)];
    while (*bucket && *bucket!=name) bucket=&(*bucket)->hashNext;
    if (*bucket) *bucket=name->hashNext;
    free(name); --gNameCount;
}
static void ReleaseSession(SESSION *s)
{
    if (s && --s->refs == 0) free(s);
}
static IO *NewIo(int kind, SESSION *s, DWORD capacity)
{
    if (gIoCount >= 8192 || offsetof(IO,data) + capacity > 64u * 1024u * 1024u - gIoBytes) { ++gDrops; return NULL; }
    IO *io = calloc(1, offsetof(IO, data) + capacity);
    if (!io) { ++gDrops; return NULL; }
    io->kind = kind; io->session = s; io->capacity = capacity;
    if (s) ++s->refs;
    ++gIoCount; gIoBytes += (unsigned)offsetof(IO,data) + capacity;
    return io;
}
static void FreeIo(IO *io)
{
    if (io->kind==RESOLVE && io->session && io->session->dns==io) io->session->dns=NULL;
    if (io->addresses) FreeAddrInfoExW(io->addresses);
    ReleaseSession(io->session); gIoBytes -= (unsigned)offsetof(IO,data) + io->capacity; free(io); --gIoCount;
}
static BOOL Issued(IO *io, BOOL ok, DWORD error)
{
    if (ok || error == ERROR_IO_PENDING || error == WSA_IO_PENDING) return TRUE;
    ++gIoErrors;
    FreeIo(io); return FALSE;
}
static BOOL DeviceRead(void)
{
    IO *io = NewIo(DRIVER_READ, NULL, PBDRV_UDP_BATCH_BYTES);
    if (!io) return FALSE;
    DWORD bytes;
    BOOL ok = DeviceIoControl(gDriver, PBDRV_IOCTL_UDP_READ, NULL, 0, io->data,
        io->capacity, &bytes, &io->ov);
    return Issued(io, ok, GetLastError());
}
static void DeviceWrite(const PBDRV_UDP_RECORD *record, const UINT8 *payload, DWORD length, UINT16 kind)
{
    DWORD control = kind==PBDRV_UDP_DIRECT ? record->controlBytes : 0;
    IO *io = NewIo(DRIVER_WRITE, NULL, sizeof(*record) + length + control);
    if (!io) return;
    PBDRV_UDP_RECORD *r = (PBDRV_UDP_RECORD *)io->data;
    *r = *record; r->kind = kind; r->bytes = sizeof(*r) + length + control; r->payloadBytes = length; r->controlBytes = control;
    if (length) memcpy(r + 1, payload, length);
    if (control) memcpy((UINT8 *)(r+1)+length,(const UINT8 *)(record+1)+record->payloadBytes,control);
    DWORD bytes;
    BOOL ok = DeviceIoControl(gDriver, PBDRV_IOCTL_UDP_WRITE, r, r->bytes, NULL, 0, &bytes, &io->ov);
    Issued(io, ok, GetLastError());
}
static BOOL SocketIo(IO *io, BOOL send)
{
    WSABUF buf = {io->size - io->used, (char *)io->data + io->used};
    DWORD bytes = 0, flags = 0;
    SOCKET socket = io->kind == UDP_READ || io->kind == UDP_SEND ? io->session->udp : io->session->tcp;
    int result = send ? WSASend(socket, &buf, 1, &bytes, 0, &io->ov, NULL) :
        WSARecv(socket, &buf, 1, &bytes, &flags, &io->ov, NULL);
    return Issued(io, result == 0, WSAGetLastError());
}
static BOOL TcpRead(SESSION *s, DWORD length, int stage)
{
    IO *io = NewIo(TCP_READ, s, length);
    if (!io) return FALSE;
    io->size = length; io->stage = stage;
    return SocketIo(io, FALSE);
}
static BOOL TcpSend(SESSION *s, const UINT8 *data, DWORD length, int stage)
{
    IO *io = NewIo(TCP_SEND, s, length);
    if (!io) return FALSE;
    io->size = length; io->stage = stage; memcpy(io->data, data, length);
    return SocketIo(io, TRUE);
}
static BOOL UdpRead(SESSION *s)
{
    IO *io = NewIo(UDP_READ, s, 65535);
    if (!io) return FALSE;
    io->size = io->capacity;
    return SocketIo(io, FALSE);
}
static void SendPacket(SESSION *s, const PBDRV_UDP_RECORD *r)
{
    DWORD header = r->family == AF_INET ? 10 : 22;
    if (r->payloadBytes > 65507 - header) { ++gDrops; return; }
    IO *io = NewIo(UDP_SEND, s, header + r->payloadBytes);
    if (!io) return;
    io->size = io->capacity;
    io->data[3] = r->family == AF_INET ? SOCKS5_ATYP_IPV4 : SOCKS5_ATYP_IPV6;
    memcpy(io->data + 4, r->remoteAddress, header - 6);
    io->data[header - 2] = (UINT8)(r->remotePort >> 8); io->data[header - 1] = (UINT8)r->remotePort;
    memcpy(io->data + header, r + 1, r->payloadBytes);
    if (!SocketIo(io, TRUE)) CloseSession(s);
}
static void CloseSession(SESSION *s)
{
    if (s->closing) return;
    s->closing = TRUE;
    if (s->dns && s->dns->resolver) GetAddrInfoExCancel(&s->dns->resolver);
    SESSION **link = &gSessions;
    while (*link && *link != s) link = &(*link)->next;
    if (*link) { *link = s->next; --gSessionCount; }
    SESSION **bucket=&gSessionBuckets[s->bucket];
    while (*bucket && *bucket!=s) bucket=&(*bucket)->hashNext;
    if (*bucket) *bucket=s->hashNext;
    if (s->tcp != INVALID_SOCKET) { closesocket(s->tcp); s->tcp = INVALID_SOCKET; }
    if (s->udp != INVALID_SOCKET) { closesocket(s->udp); s->udp = INVALID_SOCKET; }
    while (s->routes) { ROUTE *r = s->routes; s->routes = r->next; free(r); }
    while (s->first) {
        PENDING *p = s->first; s->first = p->next;
        gPendingBytes -= p->record.bytes; ++gDrops; free(p);
    }
    ReleaseSession(s); // outstanding completions keep it alive
}
static void ClosedEndpoint(UINT64 endpoint)
{
    SESSION *s = gSessions;
    while (s) { SESSION *next = s->next; if (s->endpoint == endpoint) CloseSession(s); s = next; }
    NAME **n = &gNames;
    while (*n) {
        if ((*n)->endpoint == endpoint) { NAME *old = *n; *n = old->next; FreeName(old); break; }
        n = &(*n)->next;
    }
}
static BOOL SameConfig(const PROXY_CONFIG *a, const PROXY_CONFIG *b)
{
    return a->type == b->type && a->port == b->port && a->resolved_ip == b->resolved_ip &&
        !strcmp(a->host,b->host) && !strcmp(a->username,b->username) && !strcmp(a->password,b->password);
}
static SESSION *CreateSession(const PBDRV_UDP_RECORD *record, const PROXY_CONFIG *cfg)
{
    if (gSessionCount == SESSION_LIMIT) { ++gDrops; return NULL; }
    SESSION *s = calloc(1, sizeof(*s));
    if (!s) { ++gDrops; return NULL; }
    s->endpoint = record->endpointId; s->configId = cfg->config_id; s->config = *cfg;
    s->compartment=record->compartment; s->localFamily=record->family; s->localPort=record->localPort;
    memcpy(s->localAddress,record->localAddress,16);
    s->bucket=SessionBucket(record,cfg->config_id);
    s->tcp = s->udp = INVALID_SOCKET; s->refs = 1;
    s->created = s->active = GetTickCount64();
    s->next = gSessions; gSessions = s; ++gSessionCount;
    s->hashNext=gSessionBuckets[s->bucket]; gSessionBuckets[s->bucket]=s;
    // Config add/edit resolves the proxy. No DNS lookup on the packet thread.
    if (!cfg->resolved_ip) { CloseSession(s); return NULL; }
    s->tcp = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (s->tcp == INVALID_SOCKET || !CreateIoCompletionPort((HANDLE)s->tcp, gPort, 0, 0)) {
        CloseSession(s); return NULL;
    }
    struct sockaddr_in local = {0}; local.sin_family = AF_INET;
    if (bind(s->tcp,(struct sockaddr *)&local,sizeof(local)) == SOCKET_ERROR) { CloseSession(s); return NULL; }
    GUID guid = WSAID_CONNECTEX; LPFN_CONNECTEX connectEx = NULL; DWORD got;
    if (WSAIoctl(s->tcp,SIO_GET_EXTENSION_FUNCTION_POINTER,&guid,sizeof(guid),&connectEx,sizeof(connectEx),&got,NULL,NULL)) {
        CloseSession(s); return NULL;
    }
    struct sockaddr_in remote = {0}; remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = cfg->resolved_ip; remote.sin_port = htons(cfg->port);
    IO *io = NewIo(CONNECT,s,0);
    if (!io) { CloseSession(s); return NULL; }
    BOOL ok = connectEx(s->tcp,(struct sockaddr *)&remote,sizeof(remote),NULL,0,NULL,&io->ov);
    if (!Issued(io,ok,WSAGetLastError())) { CloseSession(s); return NULL; }
    return s;
}
static void QueuePacket(SESSION *s, const PBDRV_UDP_RECORD *r)
{
    if (r->bytes > PENDING_LIMIT - gPendingBytes || r->bytes > SESSION_PENDING_LIMIT - s->pendingBytes) { ++gDrops; return; }
    PENDING *p = malloc(sizeof(*p) + r->payloadBytes + r->controlBytes);
    if (!p) { ++gDrops; return; }
    p->next = NULL; memcpy(&p->record, r, r->bytes);
    if (s->last) s->last->next = p; else s->first = p;
    s->last = p; s->pendingBytes += r->bytes; gPendingBytes += r->bytes;
}
static void Associate(SESSION *s)
{
    const UINT8 request[] = {5,3,0,1,0,0,0,0,0,0};
    if (!TcpSend(s,request,sizeof(request),REPLY_HEADER)) CloseSession(s);
}
static void SocketReady(SESSION *s, const struct sockaddr_storage *relay, int relayLength)
{
    s->udp = WSASocketW(relay->ss_family,SOCK_DGRAM,IPPROTO_UDP,NULL,0,WSA_FLAG_OVERLAPPED);
    if (s->udp == INVALID_SOCKET || !CreateIoCompletionPort((HANDLE)s->udp,gPort,0,0) ||
        connect(s->udp,(const struct sockaddr *)relay,relayLength) == SOCKET_ERROR || !UdpRead(s) || !TcpRead(s,1,CONTROL)) {
        CloseSession(s); return;
    }
    s->ready = TRUE;
    log_message("UDP ASSOCIATE established with SOCKS5 proxy %s:%u (endpoint=%llu config=%u)",
        s->config.host,s->config.port,s->endpoint,s->configId);
    while (s->first && !s->closing) {
        PENDING *p = s->first; s->first = p->next;
        s->pendingBytes -= p->record.bytes; gPendingBytes -= p->record.bytes;
        SendPacket(s,&p->record); free(p);
    }
    s->last = NULL;
}
static void CALLBACK Resolved(DWORD error, DWORD bytes, OVERLAPPED *ov)
{
    UNREFERENCED_PARAMETER(bytes);
    IO *io=CONTAINING_RECORD(ov,IO,ov);
    io->dnsError=error;
    PostQueuedCompletionStatus(gPort,0,0,ov);
}
static void ResolveRelay(SESSION *s, const UINT8 *data, DWORD length)
{
    if (length<3 || length>257) { CloseSession(s); return; }
    IO *io=NewIo(RESOLVE,s,256*sizeof(WCHAR));
    if (!io) { CloseSession(s); return; }
    if (!MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,(const char *)data,(int)length-2,(WCHAR *)io->data,255)) {
        FreeIo(io); CloseSession(s); return;
    }
    io->dnsPort=((UINT16)data[length-2]<<8)|data[length-1];
    io->hints.ai_family=AF_UNSPEC; io->hints.ai_socktype=SOCK_DGRAM; io->hints.ai_protocol=IPPROTO_UDP;
    io->timeout.tv_sec=3; s->dns=io;
    int error=GetAddrInfoExW((const WCHAR *)io->data,NULL,NS_DNS,NULL,&io->hints,&io->addresses,
        &io->timeout,&io->ov,Resolved,&io->resolver);
    if (error!=WSA_IO_PENDING) Resolved((DWORD)error,0,&io->ov);
}
static void Ready(SESSION *s, const UINT8 *data, DWORD length)
{
    struct sockaddr_storage relay = {0}; int relayLength;
    if (s->replyType == SOCKS5_ATYP_IPV4 && length == 6) {
        struct sockaddr_in *v4 = (struct sockaddr_in *)&relay;
        v4->sin_family = AF_INET; memcpy(&v4->sin_addr,data,4); memcpy(&v4->sin_port,data+4,2);
        if (!v4->sin_addr.s_addr) v4->sin_addr.s_addr = s->config.resolved_ip;
        relayLength = sizeof(*v4);
    } else if (s->replyType == SOCKS5_ATYP_IPV6 && length == 18) {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&relay;
        v6->sin6_family = AF_INET6; memcpy(&v6->sin6_addr,data,16); memcpy(&v6->sin6_port,data+16,2);
        relayLength = sizeof(*v6);
        static const UINT8 zero[16]={0};
        if (!memcmp(&v6->sin6_addr,zero,16)) {
            UINT16 port=v6->sin6_port;
            struct sockaddr_in *v4=(struct sockaddr_in *)&relay;
            memset(&relay,0,sizeof(relay)); v4->sin_family=AF_INET;
            v4->sin_addr.s_addr=s->config.resolved_ip; v4->sin_port=port; relayLength=sizeof(*v4);
        }
    } else if (s->replyType == SOCKS5_ATYP_DOMAIN) {
        ResolveRelay(s,data,length); return;
    } else {
        ++gMalformed; CloseSession(s); return;
    }
    SocketReady(s,&relay,relayLength);
}
static void TcpReceived(SESSION *s, IO *io)
{
    const UINT8 *b = io->data;
    switch (io->stage) {
    case GREETING:
        if (b[0] != 5) { CloseSession(s); break; }
        if (b[1] == 0 && !s->config.username[0]) Associate(s);
        else if (b[1] == 2 && s->config.username[0]) {
            UINT8 auth[513]; size_t user = strlen(s->config.username), pass = strlen(s->config.password);
            auth[0]=1; auth[1]=(UINT8)user; memcpy(auth+2,s->config.username,user);
            auth[2+user]=(UINT8)pass; memcpy(auth+3+user,s->config.password,pass);
            if (!TcpSend(s,auth,(DWORD)(3+user+pass),AUTHENTICATED)) CloseSession(s);
            SecureZeroMemory(auth,sizeof(auth));
        } else CloseSession(s);
        break;
    case AUTHENTICATED:
        if (b[0] == 1 && b[1] == 0) Associate(s); else CloseSession(s);
        break;
    case REPLY_HEADER:
        if (b[0] != 5 || b[1] || b[2]) { CloseSession(s); break; }
        if (b[3]!=1 && b[3]!=3 && b[3]!=4) { CloseSession(s); break; }
        s->replyType=b[3];
        if (!TcpRead(s,b[3]==1 ? 6 : b[3]==4 ? 18 : 1,b[3]==3 ? REPLY_LENGTH : REPLY_ADDRESS)) CloseSession(s);
        break;
    case REPLY_LENGTH:
        if (!b[0] || !TcpRead(s,(DWORD)b[0]+2,REPLY_ADDRESS)) CloseSession(s);
        break;
    case REPLY_ADDRESS: Ready(s,b,io->size); break;
    default: CloseSession(s); break;
    }
}
static void Packet(const PBDRV_UDP_RECORD *r)
{
    if (r->kind == PBDRV_UDP_CLOSED) { ClosedEndpoint(r->endpointId); return; }
    NAME *name = gNameBuckets[NameBucket(r->endpointId)];
    while (name && name->endpoint != r->endpointId) name = name->hashNext;
    if (!name) {
        if (gNameCount == 4096) { ++gDrops; return; }
        name = calloc(1,sizeof(*name)); if (!name) { ++gDrops; return; }
        name->endpoint=r->endpointId;
        if (!get_process_name_from_pid(r->pid,name->process,sizeof(name->process))) { free(name); ++gDrops; return; }
        name->next=gNames; gNames=name; ++gNameCount;
        unsigned bucket=NameBucket(name->endpoint);
        name->hashNext=gNameBuckets[bucket]; gNameBuckets[bucket]=name;
    }
    name->active=GetTickCount64();
    UINT32 cfgId=0, ip4; memcpy(&ip4,r->remoteAddress,4);
    RuleAction action = r->family == AF_INET ? match_rule(name->process,ip4,r->remotePort,TRUE,&cfgId) :
        match_rule_v6(name->process,r->remoteAddress,r->remotePort,TRUE,&cfgId);
    pb_report_connection(r->pid,name->process,r->family==AF_INET6,ip4,r->remoteAddress,r->remotePort,action,cfgId,TRUE);
    if (action == RULE_ACTION_DIRECT) { DeviceWrite(r,(const UINT8 *)(r+1),r->payloadBytes,PBDRV_UDP_DIRECT); return; }
    if (action != RULE_ACTION_PROXY) return;
    PROXY_CONFIG cfg;
    if (!find_proxy_config_copy(cfgId,&cfg) || cfg.type != PROXY_TYPE_SOCKS5) { ++gDrops; return; }
    SESSION *s=gSessionBuckets[SessionBucket(r,cfgId)];
    while (s && (s->endpoint != r->endpointId || s->configId != cfgId || s->compartment!=r->compartment ||
        s->localFamily!=r->family || s->localPort!=r->localPort || memcmp(s->localAddress,r->localAddress,16))) s=s->hashNext;
    if (s && !SameConfig(&s->config,&cfg)) { CloseSession(s); s=NULL; }
    if (!s) s=CreateSession(r,&cfg);
    if (!s) return;
    s->active=GetTickCount64();
    ROUTE *route=s->routes;
    while (route && (route->record.family != r->family || route->record.remotePort != r->remotePort ||
        memcmp(route->record.remoteAddress,r->remoteAddress,16))) route=route->next;
    if (!route) {
        if (s->routeCount == ROUTE_LIMIT) { ++gDrops; return; }
        route=calloc(1,sizeof(*route)); if (!route) { ++gDrops; return; }
        route->next=s->routes; s->routes=route; ++s->routeCount;
    }
    route->record=*r; route->used=s->active;
    if (s->ready) SendPacket(s,r); else QueuePacket(s,r);
}
static void Batch(const UINT8 *data, DWORD bytes)
{
    while (bytes) {
        if (bytes < sizeof(PBDRV_UDP_RECORD)) { ++gMalformed; return; }
        const PBDRV_UDP_RECORD *r=(const PBDRV_UDP_RECORD *)data;
        if (r->version != PBDRV_UDP_ABI || r->bytes < sizeof(*r) || r->bytes > bytes ||
            r->controlBytes > PBDRV_UDP_MAX_CONTROL || r->payloadBytes > PBDRV_UDP_MAX_PAYLOAD ||
            r->payloadBytes + r->controlBytes != r->bytes-sizeof(*r) ||
            !r->endpointId || (r->kind != PBDRV_UDP_DATA && r->kind != PBDRV_UDP_CLOSED) ||
            (r->kind == PBDRV_UDP_CLOSED ? (r->payloadBytes != 0 || r->controlBytes != 0) :
             (r->family != AF_INET && r->family != AF_INET6))) { ++gMalformed; return; }
        Packet(r); bytes-=r->bytes; data+=r->bytes;
    }
}
static void UdpReceived(SESSION *s, const UINT8 *b, DWORD bytes)
{
    if (bytes < 4 || b[0] || b[1] || b[2]) { ++gMalformed; return; }
    DWORD header=b[3]==1 ? 10 : b[3]==4 ? 22 : 0;
    if (!header || bytes < header) { ++gMalformed; return; }
    UINT8 remote[16]={0}; memcpy(remote,b+4,header-6);
    UINT16 port=((UINT16)b[header-2]<<8)|b[header-1];
    UINT16 family=header==10 ? AF_INET : AF_INET6;
    // Some proxies return IPv4-mapped IPv6 addresses for an IPv4 destination.
    static const UINT8 mapped[12]={0,0,0,0,0,0,0,0,0,0,255,255};
    if (family==AF_INET6 && !memcmp(remote,mapped,12)) { memmove(remote,remote+12,4); memset(remote+4,0,12); family=AF_INET; }
    ROUTE *route=s->routes;
    while (route && (route->record.family!=family || route->record.remotePort!=port || memcmp(route->record.remoteAddress,remote,16))) route=route->next;
    if (!route) { ++gMalformed; return; }
    if (port==53) snoop_dns_response(b+header,(int)(bytes-header));
    // Owner comes from the socket's SESSION, never from a global last_activity heuristic.
    DeviceWrite(&route->record,b+header,bytes-header,PBDRV_UDP_RECEIVE);
    s->active=GetTickCount64();
}
static void Expire(void)
{
    ULONGLONG now=GetTickCount64();
    if (now-gLastSweep<1000) return;
    gLastSweep=now;
    SESSION *s=gSessions;
    while (s) {
        SESSION *next=s->next;
        PROXY_CONFIG cfg;
        if ((!s->ready && now-s->created>HANDSHAKE_MS) || now-s->active>IDLE_MS ||
            !find_proxy_config_copy(s->configId,&cfg) || !SameConfig(&s->config,&cfg)) CloseSession(s);
        s=next;
    }
    NAME **name=&gNames;
    while (*name) {
        if (now-(*name)->active>IDLE_MS) { NAME *old=*name; *name=old->next; FreeName(old); }
        else name=&(*name)->next;
    }
}
static DWORD WINAPI Worker(void *arg)
{
    UNREFERENCED_PARAMETER(arg);
    BOOL stopping=FALSE;
    while (!stopping || gIoCount) {
        if (!stopping && InterlockedCompareExchange(&gStop,0,0)) {
            stopping=TRUE;
            while (gSessions) CloseSession(gSessions);
            CancelIoEx(gDriver,NULL);
        }
        DWORD bytes=0; ULONG_PTR key=0; OVERLAPPED *ov=NULL;
        BOOL ok=GetQueuedCompletionStatus(gPort,&bytes,&key,&ov,250);
        if (!ov) { if (!stopping) Expire(); continue; }
        IO *io=CONTAINING_RECORD(ov,IO,ov); SESSION *s=io->session;
        if (io->kind==RESOLVE && s->dns==io) s->dns=NULL;
        if (stopping || (s && s->closing)) { FreeIo(io); continue; }
        if (!ok) {
            ++gIoErrors;
            if (s) CloseSession(s);
            else if (io->kind==DRIVER_READ) InterlockedExchange(&gStop,1);
            FreeIo(io); continue;
        }
        if (io->kind==TCP_READ || io->kind==TCP_SEND) {
            if (!bytes) { CloseSession(s); FreeIo(io); continue; }
            io->used+=bytes;
            if (io->used<io->size) {
                memset(&io->ov,0,sizeof(io->ov));
                if (!SocketIo(io,io->kind==TCP_SEND)) CloseSession(s);
                continue;
            }
        }
        switch (io->kind) {
        case RESOLVE: {
            PADDRINFOEXW address=io->addresses;
            // The proxy control transport is IPv4; prefer A when a relay name
            // resolves to both families, retaining an IPv6-only fallback.
            for (PADDRINFOEXW a=io->addresses;a;a=a->ai_next) if (a->ai_family==AF_INET) { address=a; break; }
            while (address && address->ai_family!=AF_INET && address->ai_family!=AF_INET6) address=address->ai_next;
            if (io->dnsError || !address || address->ai_addrlen>sizeof(struct sockaddr_storage)) { CloseSession(s); break; }
            struct sockaddr_storage relay={0}; memcpy(&relay,address->ai_addr,address->ai_addrlen);
            if (relay.ss_family==AF_INET) ((struct sockaddr_in *)&relay)->sin_port=htons(io->dnsPort);
            else ((struct sockaddr_in6 *)&relay)->sin6_port=htons(io->dnsPort);
            SocketReady(s,&relay,(int)address->ai_addrlen); break;
        }
        case DRIVER_READ:
            if (!DeviceRead()) InterlockedExchange(&gStop,1);
            Batch(io->data,bytes);
            break;
        case CONNECT: {
            if (setsockopt(s->tcp,SOL_SOCKET,SO_UPDATE_CONNECT_CONTEXT,NULL,0)==SOCKET_ERROR) { CloseSession(s); break; }
            struct tcp_keepalive keepalive={1,10000,2000}; DWORD returned;
            WSAIoctl(s->tcp,SIO_KEEPALIVE_VALS,&keepalive,sizeof(keepalive),NULL,0,&returned,NULL,NULL);
            const UINT8 greeting[]={5,1,s->config.username[0] ? 2 : 0};
            if (!TcpSend(s,greeting,sizeof(greeting),GREETING)) CloseSession(s);
            break;
        }
        case TCP_SEND:
            if (!TcpRead(s,io->stage==REPLY_HEADER ? 4 : 2,io->stage)) CloseSession(s);
            break;
        case TCP_READ: TcpReceived(s,io); break;
        case UDP_READ:
            UdpReceived(s,io->data,bytes);
            if (!UdpRead(s)) CloseSession(s);
            break;
        case UDP_SEND: if (bytes != io->size) { ++gDrops; CloseSession(s); } break;
        default: break;
        }
        FreeIo(io);
        Expire();
    }
    while (gNames) { NAME *old=gNames; gNames=old->next; FreeName(old); }
    gNameCount=0;
    log_message("UDP channel stopped: drops=%llu malformed=%llu io_errors=%llu",gDrops,gMalformed,gIoErrors);
    return 0;
}
BOOL pb_udp_start(HANDLE driver)
{
    if (gThread) return FALSE;
    gPort=CreateIoCompletionPort(driver,NULL,0,1);
    if (!gPort) return FALSE;
    gDriver=driver; InterlockedExchange(&gStop,0);
    gDrops=gMalformed=gIoErrors=0;
    // Queue before the worker starts; failed startup cancels and drains issued I/O.
    BOOL ready=TRUE;
    if (!DeviceRead()) ready=FALSE;
    if (!ready) InterlockedExchange(&gStop,1);
    gThread=CreateThread(NULL,0,Worker,NULL,0,NULL);
    if (!gThread) {
        InterlockedExchange(&gStop,1);
        Worker(NULL); CloseHandle(gPort); gPort=NULL; gDriver=INVALID_HANDLE_VALUE; return FALSE;
    }
    if (!ready) { pb_udp_stop(); return FALSE; }
    return TRUE;
}
void pb_udp_stop(void)
{
    if (!gThread) return;
    InterlockedExchange(&gStop,1); PostQueuedCompletionStatus(gPort,0,0,NULL);
    WaitForSingleObject(gThread,INFINITE); CloseHandle(gThread); gThread=NULL;
    CloseHandle(gPort); gPort=NULL; gDriver=INVALID_HANDLE_VALUE;
}

// Retained internal symbol; startup is owned by pb_driver_start, not a UDP listener.
DWORD WINAPI udp_relay_server(LPVOID arg) { UNREFERENCED_PARAMETER(arg); return 0; }
