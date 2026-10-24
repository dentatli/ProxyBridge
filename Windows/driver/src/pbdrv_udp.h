#ifndef PBDRV_UDP_H
#define PBDRV_UDP_H
#include <wdf.h>
#include "ProxyBridgeDrv_ioctl.h"
NTSTATUS PbUdpDeviceInit(WDFDEVICE device);
NTSTATUS PbUdpStart(PDEVICE_OBJECT device, HANDLE engine, const GUID *provider, const GUID *sublayer);
NTSTATUS PbUdpStop(void);
void PbUdpReset(void);
void PbUdpRead(WDFREQUEST request);
NTSTATUS PbUdpWrite(const PBDRV_UDP_RECORD *record, ULONG length);
void PbUdpStats(PBDRV_UDP_STATS *stats);
BOOLEAN PbUdpSelected(UINT16 family, UINT32 pid, const void *app,
                      const UINT8 *remoteAddress);
#endif
