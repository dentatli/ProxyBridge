/*
 * ProxyBridgeDrv_user.c - user-mode glue between ProxyBridge and the WFP driver.
 *
 * Two jobs:
 *   1) push config + watch list to the driver over IOCTL (pbdrv_configure / pbdrv_set_watchlist);
 *   2) recover the ORIGINAL destination of a redirected connection on the relay's
 *      accepted socket (pbdrv_get_original_dest), replacing the source-port lookup.
 *
 * This is drop-in for the existing relay: after accept(), call pbdrv_get_original_dest()
 * instead of get_connection_full(client_port, ...). No packet mangling, no correlation.
 *
 * Link with ws2_32 and fwpuclnt is NOT required for the query path (it is a plain WSAIoctl).
 */
#include <winsock2.h>
#include <ws2ipdef.h>
#include <mstcpip.h>       // SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS / _CONTEXT
#include <ws2tcpip.h>
#include "ProxyBridgeDrv_ioctl.h"

// ---- driver handle / config ------------------------------------------------

HANDLE pbdrv_open(void)
{
    return CreateFileW(PBDRV_USER_PATH, GENERIC_READ | GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
}

BOOL pbdrv_control(HANDLE h, DWORD code, void *input, DWORD inputBytes,
                    void *output, DWORD outputBytes, DWORD *returned)
{
    OVERLAPPED ov = {0};
    HANDLE event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!event) return FALSE;
    // Low event bit suppresses IOCP notification for these synchronous control
    // operations: their stack OVERLAPPED must never enter the UDP event loop.
    ov.hEvent = (HANDLE)((ULONG_PTR)event | 1);
    BOOL ok = DeviceIoControl(h, code, input, inputBytes, output, outputBytes, returned, &ov);
    if (!ok && GetLastError() == ERROR_IO_PENDING) ok = GetOverlappedResult(h, &ov, returned, TRUE);
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(event); SetLastError(error); return ok;
}

BOOL pbdrv_configure(HANDLE h, const PBDRV_CONFIG *cfg)
{
    DWORD ret = 0;
    return pbdrv_control(h, PBDRV_IOCTL_SET_CONFIG, (LPVOID)cfg, sizeof(*cfg), NULL, 0, &ret);
}

// Push the watch list (image-name suffixes to redirect). User mode derives this from the
// GUI rules ("which processes have any rule"); the proxy/direct/block decision stays in
// the relay's rule engine, not the driver.
BOOL pbdrv_set_watchlist(HANDLE h, const PBDRV_WATCHLIST *wl)
{
    DWORD ret = 0;
    DWORD len = (DWORD)(FIELD_OFFSET(PBDRV_WATCHLIST, entries) + (SIZE_T)wl->count * sizeof(PBDRV_WATCH_ENTRY));
    return pbdrv_control(h, PBDRV_IOCTL_SET_WATCHLIST, (LPVOID)wl, len, NULL, 0, &ret);
}

BOOL pbdrv_enable(HANDLE h, BOOL on)
{
    DWORD ret = 0;
    return pbdrv_control(h, on ? PBDRV_IOCTL_ENABLE : PBDRV_IOCTL_DISABLE, NULL, 0, NULL, 0, &ret);
}

// Query a redirected UDP flow's original destination by its source endpoint (in/out `q`).
BOOL pbdrv_udp_query(HANDLE h, PBDRV_UDP_QUERY *q)
{
    DWORD ret = 0;
    return pbdrv_control(h, PBDRV_IOCTL_QUERY_UDP, q, sizeof(*q), q, sizeof(*q), &ret) && ret >= sizeof(*q);
}

// Drain the driver's connection-event ring into buf[0..maxCount). Returns the count via *got.
// Each event is one outbound connect the monitor callout observed (for the connection log).
BOOL pbdrv_pop_events(HANDLE h, PBDRV_EVENT *buf, DWORD maxCount, DWORD *got)
{
    DWORD ret = 0;
    BOOL ok = pbdrv_control(h, PBDRV_IOCTL_POP_EVENTS, NULL, 0,
                              buf, maxCount * (DWORD)sizeof(PBDRV_EVENT), &ret);
    *got = ok ? (ret / (DWORD)sizeof(PBDRV_EVENT)) : 0;
    return ok;
}

// ---- recover the original destination on a redirected socket ---------------
//
// `accepted` is the socket returned by accept() on the relay listener. On success,
// *ctx is filled with the true destination (and family/protocol/pid) the driver stashed.
BOOL pbdrv_get_original_dest(SOCKET accepted, PBDRV_REDIRECT_CTX *ctx)
{
    DWORD bytes = 0;
    // The driver set this via req->localRedirectContext; WFP returns it verbatim here.
    if (WSAIoctl(accepted, SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT, NULL, 0,
                 ctx, sizeof(*ctx), &bytes, NULL, NULL) == 0 && bytes >= sizeof(*ctx))
        return TRUE;
    return FALSE;
}

// UDP uses the separate versioned packet channel; it has no accepted socket
// and must not infer per-datagram ownership from a shared UDP socket's context.
