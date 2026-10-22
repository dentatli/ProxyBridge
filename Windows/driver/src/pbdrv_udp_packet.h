#ifndef PBDRV_UDP_PACKET_H
#define PBDRV_UDP_PACKET_H
// Pure packet construction, shared by the kernel implementation and offline
// diagnostic tools. Caller validates the record and provides sufficient storage.
#include "ProxyBridgeDrv_ioctl.h"
static UINT32 PbUdpChecksumAdd(const UINT8 *p, UINT32 length, UINT32 sum)
{
    while (length > 1) { sum += ((UINT32)p[0] << 8) | p[1]; p += 2; length -= 2; }
    if (length) sum += (UINT32)p[0] << 8;
    return sum;
}
static UINT16 PbUdpChecksumFinish(UINT32 sum)
{ while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16); return (UINT16)~sum; }
static void PbUdpPut16(UINT8 *p, UINT32 v) { p[0] = (UINT8)(v >> 8); p[1] = (UINT8)v; }
static UINT32 PbUdpBuildDatagram(const PBDRV_UDP_RECORD *r, UINT8 *buffer)
{
    BOOLEAN receive = r->kind == PBDRV_UDP_RECEIVE;
    UINT32 ipBytes = receive ? (r->family == 2 /* AF_INET */ ? 20 : 40) : 0;
    UINT32 bytes = ipBytes + 8 + r->payloadBytes;
    UINT8 *udp = buffer + ipBytes;
    const UINT8 *src = receive ? r->remoteAddress : r->localAddress;
    const UINT8 *dst = receive ? r->localAddress : r->remoteAddress;
    for (UINT32 n = 0; n < ipBytes + 8; ++n) buffer[n] = 0;
    PbUdpPut16(udp, receive ? r->remotePort : r->localPort);
    PbUdpPut16(udp + 2, receive ? r->localPort : r->remotePort);
    PbUdpPut16(udp + 4, 8 + r->payloadBytes);
    RtlCopyMemory(udp + 8, r + 1, r->payloadBytes);
    UINT32 sum = PbUdpChecksumAdd(src, r->family == 2 ? 4 : 16, 0);
    sum = PbUdpChecksumAdd(dst, r->family == 2 ? 4 : 16, sum) + 17 /* UDP */ + 8 + r->payloadBytes;
    UINT16 checksum = PbUdpChecksumFinish(PbUdpChecksumAdd(udp, 8 + r->payloadBytes, sum));
    PbUdpPut16(udp + 6, checksum ? checksum : 0xffff);
    if (receive && r->family == 2) {
        buffer[0] = 0x45; PbUdpPut16(buffer + 2, bytes); buffer[8] = 64; buffer[9] = 17;
        RtlCopyMemory(buffer + 12, src, 4); RtlCopyMemory(buffer + 16, dst, 4);
        PbUdpPut16(buffer + 10, PbUdpChecksumFinish(PbUdpChecksumAdd(buffer, 20, 0)));
    } else if (receive) {
        buffer[0] = 0x60; PbUdpPut16(buffer + 4, bytes - 40); buffer[6] = 17; buffer[7] = 64;
        RtlCopyMemory(buffer + 8, src, 16); RtlCopyMemory(buffer + 24, dst, 16);
    }
    return bytes;
}
#endif
