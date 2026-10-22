// UDP packet identity is carried with the payload, never reconstructed from a
// mutable source->destination map. All allocations and queues are bounded.
#include <initguid.h>
#define NDIS_SUPPORT_NDIS6 1
#include <ntddk.h>
#pragma warning(push)
#pragma warning(disable:4201)
#include <fwpsk.h>
#include <fwpmk.h>
#include <ndis.h>
#pragma warning(pop)
#include "pbdrv_udp.h"
#include "pbdrv_udp_packet.h"

#define TAG 'uDbP'
#define BUCKETS 256u
#define MAX_ENDPOINTS 4096u
#define MAX_QUEUED_BYTES (2u * 1024u * 1024u)
#define MAX_QUEUED_PACKETS 2048u
#define MAX_INJECT_BYTES (2u * 1024u * 1024u)
#define MAX_INJECTIONS 1024u

typedef struct ENDPOINT {
    LIST_ENTRY link;
    LIST_ENTRY byId;
    UINT64 handle, id;
    UINT32 pid;
    UINT16 family, port;
    WCHAR image[PBDRV_NAME_LEN];
} ENDPOINT;
typedef struct PACKET {
    LIST_ENTRY link;
    PBDRV_UDP_RECORD record;
    // payload immediately follows record
} PACKET;
typedef struct INJECTION {
    NET_BUFFER_LIST *nbl;
    PMDL mdl;
    ULONG bytes;
    FWPS_TRANSPORT_SEND_PARAMS0 send;
    UINT8 remote[16];
    UINT8 data[1];
} INJECTION;

static KSPIN_LOCK gLock;
static LIST_ENTRY gEndpoints[BUCKETS], gById[BUCKETS], gPackets;
static ULONG gEndpointCount, gQueueBytes, gQueueCount;
static volatile LONG64 gNextId;
static volatile LONG gInjectBytes;
static BOOLEAN gActive, gWorkQueued;
static WDFQUEUE gReads;
static WDFWORKITEM gWork;
static HANDLE gInject4, gInject6, gNblPool;
static UINT32 gCallouts[6];
__declspec(align(8)) static PBDRV_UDP_STATS gStats;
static EX_RUNDOWN_REF gWriters;
static BOOLEAN gInitialized, gWritersReady, gStarted;
static KEVENT gInjectIdle;
static volatile LONG gInjectCount;

// Unique to this module; no shared sample GUIDs.
DEFINE_GUID(UDP_AUTH4, 0x8cf4db71,0x7ea5,0x4d8b,0x89,0x13,0x13,0x7a,0xf1,0x44,0xc1,0x01);
DEFINE_GUID(UDP_AUTH6, 0x8cf4db71,0x7ea5,0x4d8b,0x89,0x13,0x13,0x7a,0xf1,0x44,0xc1,0x02);
DEFINE_GUID(UDP_DATA4, 0x8cf4db71,0x7ea5,0x4d8b,0x89,0x13,0x13,0x7a,0xf1,0x44,0xc1,0x03);
DEFINE_GUID(UDP_DATA6, 0x8cf4db71,0x7ea5,0x4d8b,0x89,0x13,0x13,0x7a,0xf1,0x44,0xc1,0x04);
DEFINE_GUID(UDP_CLOSE4,0x8cf4db71,0x7ea5,0x4d8b,0x89,0x13,0x13,0x7a,0xf1,0x44,0xc1,0x05);
DEFINE_GUID(UDP_CLOSE6,0x8cf4db71,0x7ea5,0x4d8b,0x89,0x13,0x13,0x7a,0xf1,0x44,0xc1,0x06);

static ULONG Bucket(UINT64 h) { return (ULONG)(h ^ (h >> 32)) % BUCKETS; }
// gLock held; no pointer escapes the lock.
static ENDPOINT *Find(UINT64 handle)
{
    LIST_ENTRY *head = &gEndpoints[Bucket(handle)];
    for (LIST_ENTRY *l = head->Flink; l != head; l = l->Flink) {
        ENDPOINT *e = CONTAINING_RECORD(l, ENDPOINT, link);
        if (e->handle == handle) return e;
    }
    return NULL;
}
static ENDPOINT *FindId(UINT64 id)
{
    LIST_ENTRY *head = &gById[Bucket(id)];
    for (LIST_ENTRY *l = head->Flink; l != head; l = l->Flink) {
        ENDPOINT *e = CONTAINING_RECORD(l, ENDPOINT, byId);
        if (e->id == id) return e;
    }
    return NULL;
}

// Called with gLock; work item completion serializes queue consumption.
static void Schedule(void)
{
    if (!gWorkQueued && gActive) {
        gWorkQueued = TRUE;
        WdfWorkItemEnqueue(gWork);
    }
}
static void Enqueue(PACKET *p)
{
    KIRQL irql;
    KeAcquireSpinLock(&gLock, &irql);
    if (!gActive || (p->record.kind == PBDRV_UDP_DATA && FindId(p->record.endpointId) == NULL) ||
        gQueueCount == MAX_QUEUED_PACKETS ||
        p->record.bytes > MAX_QUEUED_BYTES - gQueueBytes) {
        InterlockedIncrement64((LONG64 *)&gStats.queueDrops);
        KeReleaseSpinLock(&gLock, irql);
        ExFreePoolWithTag(p, TAG);
        return;
    }
    InsertTailList(&gPackets, &p->link);
    gQueueBytes += p->record.bytes; ++gQueueCount;
    Schedule();
    KeReleaseSpinLock(&gLock, irql);
}

static BOOLEAN CopyRecord(_Out_writes_bytes_(capacity) UINT8 *destination, size_t capacity,
    _In_reads_bytes_(bytes) const void *source, ULONG bytes)
{
    if (bytes > capacity) return FALSE;
    RtlCopyMemory(destination, source, bytes);
    return TRUE;
}

EVT_WDF_WORKITEM Drain;
_Use_decl_annotations_
void Drain(WDFWORKITEM work)
{
    UNREFERENCED_PARAMETER(work);
    for (;;) {
        KIRQL irql;
        KeAcquireSpinLock(&gLock, &irql);
        if (!gActive || IsListEmpty(&gPackets)) {
            gWorkQueued = FALSE;
            KeReleaseSpinLock(&gLock, irql);
            return;
        }
        KeReleaseSpinLock(&gLock, irql);
        WDFREQUEST request;
        NTSTATUS status = WdfIoQueueRetrieveNextRequest(gReads, &request);
        if (!NT_SUCCESS(status)) {
            // Recheck under lock after publishing idle. A read forwarded after
            // this point schedules another pass; existing queued reads are
            // checked once more to cover ForwardToIoQueue racing this pass.
            KeAcquireSpinLock(&gLock, &irql);
            gWorkQueued = FALSE;
            ULONG queued = 0;
            WdfIoQueueGetState(gReads, &queued, NULL);
            if (queued != 0) Schedule();
            KeReleaseSpinLock(&gLock, irql);
            return;
        }
        UINT8 *out; size_t capacity;
        status = WdfRequestRetrieveOutputBuffer(request,
            sizeof(PBDRV_UDP_RECORD) + PBDRV_UDP_MAX_PAYLOAD + PBDRV_UDP_MAX_CONTROL, (void **)&out, &capacity);
        ULONG written = 0;
        if (NT_SUCCESS(status)) {
            capacity = min(capacity, PBDRV_UDP_BATCH_BYTES);
            for (;;) {
                KeAcquireSpinLock(&gLock, &irql);
                PACKET *p = IsListEmpty(&gPackets) ? NULL :
                    CONTAINING_RECORD(gPackets.Flink, PACKET, link);
                if (!gActive || p == NULL || written > capacity || p->record.bytes > capacity - written) {
                    KeReleaseSpinLock(&gLock, irql); break;
                }
                RemoveEntryList(&p->link);
                gQueueBytes -= p->record.bytes; --gQueueCount;
                InterlockedIncrement64((LONG64 *)&gStats.delivered);
                KeReleaseSpinLock(&gLock, irql);
                if (!CopyRecord(out + written, capacity - written, &p->record, p->record.bytes)) {
                    ExFreePoolWithTag(p, TAG); status = STATUS_DATA_ERROR; break;
                }
                written += p->record.bytes;
                ExFreePoolWithTag(p, TAG);
            }
        }
        WdfRequestCompleteWithInformation(request, status, written);
    }
}

NTSTATUS PbUdpDeviceInit(WDFDEVICE device)
{
    KeInitializeSpinLock(&gLock);
    KeInitializeEvent(&gInjectIdle, NotificationEvent, TRUE);
    InitializeListHead(&gPackets);
    for (ULONG i = 0; i < BUCKETS; ++i) { InitializeListHead(&gEndpoints[i]); InitializeListHead(&gById[i]); }
    gInitialized = TRUE;
    WDF_IO_QUEUE_CONFIG queue;
    WDF_IO_QUEUE_CONFIG_INIT(&queue, WdfIoQueueDispatchManual);
    queue.PowerManaged = WdfFalse;
    NTSTATUS status = WdfIoQueueCreate(device, &queue, WDF_NO_OBJECT_ATTRIBUTES, &gReads);
    if (!NT_SUCCESS(status)) return status;
    WDF_WORKITEM_CONFIG work;
    WDF_WORKITEM_CONFIG_INIT(&work, Drain);
    work.AutomaticSerialization = FALSE;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.ParentObject = device;
    return WdfWorkItemCreate(&work, &attributes, &gWork);
}

void PbUdpRead(WDFREQUEST request)
{
    KIRQL irql;
    KeAcquireSpinLock(&gLock, &irql); BOOLEAN active = gActive; KeReleaseSpinLock(&gLock, irql);
    if (!active) { WdfRequestComplete(request, STATUS_DEVICE_NOT_READY); return; }
    void *buffer;
    NTSTATUS status = WdfRequestRetrieveOutputBuffer(request,
        sizeof(PBDRV_UDP_RECORD) + PBDRV_UDP_MAX_PAYLOAD + PBDRV_UDP_MAX_CONTROL, &buffer, NULL);
    if (NT_SUCCESS(status)) status = WdfRequestForwardToIoQueue(request, gReads);
    if (!NT_SUCCESS(status)) { WdfRequestComplete(request, status); return; }
    KeAcquireSpinLock(&gLock, &irql); Schedule(); KeReleaseSpinLock(&gLock, irql);
}

static NTSTATUS NTAPI Notify(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID *key, FWPS_FILTER1 *filter)
{ UNREFERENCED_PARAMETER(type); UNREFERENCED_PARAMETER(key); UNREFERENCED_PARAMETER(filter); return STATUS_SUCCESS; }

static void Addresses(const FWPS_INCOMING_VALUES0 *v, UINT32 local, UINT32 remote,
                      UINT16 family, UINT8 *l, UINT8 *r)
{
    if (family == AF_INET) {
        UINT32 a = RtlUlongByteSwap(v->incomingValue[local].value.uint32);
        UINT32 b = RtlUlongByteSwap(v->incomingValue[remote].value.uint32);
        RtlCopyMemory(l, &a, 4); RtlCopyMemory(r, &b, 4);
    } else {
        RtlCopyMemory(l, v->incomingValue[local].value.byteArray16->byteArray16, 16);
        RtlCopyMemory(r, v->incomingValue[remote].value.byteArray16->byteArray16, 16);
    }
}
static void NTAPI Authorize(const FWPS_INCOMING_VALUES0 *v, const FWPS_INCOMING_METADATA_VALUES0 *m,
    void *data, const void *context, const FWPS_FILTER1 *filter, UINT64 flow, FWPS_CLASSIFY_OUT0 *out)
{
    UNREFERENCED_PARAMETER(data); UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(filter); UNREFERENCED_PARAMETER(flow);
    out->actionType = FWP_ACTION_CONTINUE;
    BOOLEAN v6 = v->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6;
    UINT32 proto = v6 ? FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL : FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL;
    if (v->incomingValue[proto].value.uint8 != IPPROTO_UDP) return;
    UINT32 app = v6 ? FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_APP_ID : FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID;
    UINT32 port = v6 ? FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT : FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT;
    UINT32 local = v6 ? FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS : FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS;
    UINT32 remote = v6 ? FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS : FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS;
    FWP_BYTE_BLOB *image = v->incomingValue[app].value.byteBlob;
    UINT8 la[16] = {0}, ra[16] = {0};
    Addresses(v, local, remote, v6 ? AF_INET6 : AF_INET, la, ra);
    UINT32 pid = FWPS_IS_METADATA_FIELD_PRESENT(m, FWPS_METADATA_FIELD_PROCESS_ID) ? (UINT32)m->processId : 0;
    BOOLEAN selected = PbUdpSelected(v6 ? AF_INET6 : AF_INET, pid, image, ra);
    if (!FWPS_IS_METADATA_FIELD_PRESENT(m, FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE)) {
        if (selected && (out->rights & FWPS_RIGHT_ACTION_WRITE)) {
            InterlockedIncrement64((LONG64 *)&gStats.invalidMetadata);
            out->actionType = FWP_ACTION_BLOCK; out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        }
        return;
    }
    // Also remember unselected endpoints so live watchlist changes apply to
    // existing sockets without relying on a subsequent ALE reauthorization.
    ENDPOINT *candidate = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*candidate), TAG);
    KIRQL irql;
    KeAcquireSpinLock(&gLock, &irql);
    ENDPOINT *e = Find(m->transportEndpointHandle);
    if (gActive && e == NULL && candidate != NULL && gEndpointCount < MAX_ENDPOINTS) {
        e = candidate; candidate = NULL;
        e->handle = m->transportEndpointHandle;
        e->id = (UINT64)InterlockedIncrement64(&gNextId);
        e->family = v6 ? AF_INET6 : AF_INET;
        e->port = v->incomingValue[port].value.uint16; e->pid = pid;
        if (image && image->data) {
            ULONG chars = image->size / sizeof(WCHAR);
            const WCHAR *s = (const WCHAR *)image->data;
            while (chars && !s[chars - 1]) --chars;
            ULONG copy = min(chars, PBDRV_NAME_LEN - 1);
            RtlCopyMemory(e->image, s + chars - copy, copy * sizeof(WCHAR));
        }
        InsertTailList(&gEndpoints[Bucket(e->handle)], &e->link);
        InsertTailList(&gById[Bucket(e->id)], &e->byId); ++gEndpointCount;
    }
    BOOLEAN failed = gActive && e == NULL && selected;
    if (failed) InterlockedIncrement64((LONG64 *)&gStats.endpointLimit);
    KeReleaseSpinLock(&gLock, irql);
    if (candidate) ExFreePoolWithTag(candidate, TAG);
    if (failed && (out->rights & FWPS_RIGHT_ACTION_WRITE)) {
        out->actionType = FWP_ACTION_BLOCK; out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
}

static void NTAPI Datagram(const FWPS_INCOMING_VALUES0 *v, const FWPS_INCOMING_METADATA_VALUES0 *m,
    void *data, const void *context, const FWPS_FILTER1 *filter, UINT64 flow, FWPS_CLASSIFY_OUT0 *out)
{
    UNREFERENCED_PARAMETER(context); UNREFERENCED_PARAMETER(filter); UNREFERENCED_PARAMETER(flow);
    out->actionType = FWP_ACTION_CONTINUE;
    BOOLEAN v6 = v->layerId == FWPS_LAYER_DATAGRAM_DATA_V6;
    UINT32 proto = v6 ? FWPS_FIELD_DATAGRAM_DATA_V6_IP_PROTOCOL : FWPS_FIELD_DATAGRAM_DATA_V4_IP_PROTOCOL;
    UINT32 direction = v6 ? FWPS_FIELD_DATAGRAM_DATA_V6_DIRECTION : FWPS_FIELD_DATAGRAM_DATA_V4_DIRECTION;
    if (v->incomingValue[proto].value.uint8 != IPPROTO_UDP ||
        v->incomingValue[direction].value.uint32 != FWP_DIRECTION_OUTBOUND ||
        !(out->rights & FWPS_RIGHT_ACTION_WRITE) || data == NULL) return;
    FWPS_PACKET_INJECTION_STATE state = FwpsQueryPacketInjectionState0(v6 ? gInject6 : gInject4, data, NULL);
    if (state == FWPS_PACKET_INJECTED_BY_SELF || state == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF) return;
    if (!FWPS_IS_METADATA_FIELD_PRESENT(m, FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE)) {
        InterlockedIncrement64((LONG64 *)&gStats.invalidMetadata); return;
    }
    // Copy bounded endpoint identity under lock; never use a freed ENDPOINT.
    ENDPOINT saved = {0};
    KIRQL irql;
    KeAcquireSpinLock(&gLock, &irql);
    ENDPOINT *e = gActive ? Find(m->transportEndpointHandle) : NULL;
    if (e) saved = *e;
    KeReleaseSpinLock(&gLock, irql);
    if (e == NULL) return;
    PBDRV_UDP_RECORD record = {0};
    record.version = PBDRV_UDP_ABI; record.kind = PBDRV_UDP_DATA;
    record.family = v6 ? AF_INET6 : AF_INET;
    record.endpointId = saved.id; record.pid = saved.pid;
    Addresses(v, v6 ? FWPS_FIELD_DATAGRAM_DATA_V6_IP_LOCAL_ADDRESS : FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_ADDRESS,
        v6 ? FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_ADDRESS : FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_ADDRESS,
        record.family, record.localAddress, record.remoteAddress);
    FWP_BYTE_BLOB image = {sizeof(saved.image), (UINT8 *)saved.image};
    if (!PbUdpSelected(record.family, saved.pid, &image, record.remoteAddress)) return;
    record.localPort = v->incomingValue[v6 ? FWPS_FIELD_DATAGRAM_DATA_V6_IP_LOCAL_PORT : FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_PORT].value.uint16;
    record.remotePort = v->incomingValue[v6 ? FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_PORT : FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT].value.uint16;
    record.compartment = FWPS_IS_METADATA_FIELD_PRESENT(m, FWPS_METADATA_FIELD_COMPARTMENT_ID) ? m->compartmentId : UNSPECIFIED_COMPARTMENT_ID;
    record.remoteScope = FWPS_IS_METADATA_FIELD_PRESENT(m, FWPS_METADATA_FIELD_REMOTE_SCOPE_ID) ? m->remoteScopeId.Value : 0;
    record.interfaceIndex = v->incomingValue[v6 ? FWPS_FIELD_DATAGRAM_DATA_V6_INTERFACE_INDEX : FWPS_FIELD_DATAGRAM_DATA_V4_INTERFACE_INDEX].value.uint32;
    record.subInterfaceIndex = v->incomingValue[v6 ? FWPS_FIELD_DATAGRAM_DATA_V6_SUB_INTERFACE_INDEX : FWPS_FIELD_DATAGRAM_DATA_V4_SUB_INTERFACE_INDEX].value.uint32;
    // From here all failures are accounted drops; never bypass proxy/block rules.
    out->actionType = FWP_ACTION_BLOCK; out->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
    out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    record.controlBytes = FWPS_IS_METADATA_FIELD_PRESENT(m, FWPS_METADATA_FIELD_TRANSPORT_CONTROL_DATA) ? m->controlDataLength : 0;
    if (record.controlBytes > PBDRV_UDP_MAX_CONTROL || (record.controlBytes && !m->controlData)) {
        InterlockedIncrement64((LONG64 *)&gStats.invalidMetadata); return;
    }
    for (NET_BUFFER_LIST *nbl = data; nbl; nbl = NET_BUFFER_LIST_NEXT_NBL(nbl)) {
        for (NET_BUFFER *nb = NET_BUFFER_LIST_FIRST_NB(nbl); nb; nb = NET_BUFFER_NEXT_NB(nb)) {
            ULONG length = NET_BUFFER_DATA_LENGTH(nb);
            // Outbound DATAGRAM_DATA starts at the UDP header, including zero-length payloads.
            if (length < 8 || length - 8 > PBDRV_UDP_MAX_PAYLOAD) {
                InterlockedIncrement64((LONG64 *)&gStats.invalidMetadata); continue;
            }
            PACKET *p = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*p) + length - 8 + record.controlBytes, TAG);
            if (p == NULL) { InterlockedIncrement64((LONG64 *)&gStats.allocationDrops); continue; }
            record.payloadBytes = length - 8; record.bytes = sizeof(record) + record.payloadBytes + record.controlBytes;
            p->record = record;
            UINT8 udp[8];
            UINT8 *header = NdisGetDataBuffer(nb, 8, udp, 1, 0);
            if (header == NULL || (((ULONG)header[4] << 8) | header[5]) != length) {
                ExFreePoolWithTag(p, TAG); InterlockedIncrement64((LONG64 *)&gStats.invalidMetadata); continue;
            }
            NdisAdvanceNetBufferDataStart(nb, 8, FALSE, NULL);
            UINT8 *payload = record.payloadBytes ? NdisGetDataBuffer(nb, record.payloadBytes, (UINT8 *)(&p->record + 1), 1, 0) : NULL;
            if (payload && payload != (UINT8 *)(&p->record + 1))
                RtlCopyMemory(&p->record + 1, payload, record.payloadBytes);
            NdisRetreatNetBufferDataStart(nb, 8, 0, NULL);
            if (record.payloadBytes && payload == NULL) {
                ExFreePoolWithTag(p, TAG); InterlockedIncrement64((LONG64 *)&gStats.allocationDrops); continue;
            }
            if (record.controlBytes) RtlCopyMemory((UINT8 *)(&p->record + 1) + record.payloadBytes, m->controlData, record.controlBytes);
            InterlockedIncrement64((LONG64 *)&gStats.captured); Enqueue(p);
        }
    }
}

static void NTAPI Closed(const FWPS_INCOMING_VALUES0 *v, const FWPS_INCOMING_METADATA_VALUES0 *m,
    void *data, const void *context, const FWPS_FILTER1 *filter, UINT64 flow, FWPS_CLASSIFY_OUT0 *out)
{
    UNREFERENCED_PARAMETER(v); UNREFERENCED_PARAMETER(data); UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(filter); UNREFERENCED_PARAMETER(flow);
    out->actionType = FWP_ACTION_CONTINUE;
    if (!FWPS_IS_METADATA_FIELD_PRESENT(m, FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE)) return;
    KIRQL irql;
    KeAcquireSpinLock(&gLock, &irql);
    ENDPOINT *e = Find(m->transportEndpointHandle);
    UINT64 id = e ? e->id : 0;
    if (e) { RemoveEntryList(&e->link); RemoveEntryList(&e->byId); --gEndpointCount; }
    KeReleaseSpinLock(&gLock, irql);
    if (e) ExFreePoolWithTag(e, TAG);
    if (id) {
        PACKET *p = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*p), TAG);
        if (p) {
            p->record.bytes = sizeof(p->record); p->record.version = PBDRV_UDP_ABI;
            p->record.kind = PBDRV_UDP_CLOSED; p->record.endpointId = id;
            Enqueue(p);
        } else InterlockedIncrement64((LONG64 *)&gStats.allocationDrops);
    }
}

static void FreeInjection(INJECTION *i)
{
    if (i->nbl) FwpsFreeNetBufferList0(i->nbl);
    if (i->mdl) IoFreeMdl(i->mdl);
    InterlockedExchangeAdd(&gInjectBytes, -(LONG)i->bytes);
    ExFreePoolWithTag(i, TAG);
    KIRQL irql; KeAcquireSpinLock(&gLock, &irql);
    if (--gInjectCount == 0) KeSetEvent(&gInjectIdle, IO_NO_INCREMENT, FALSE);
    KeReleaseSpinLock(&gLock, irql);
}
static void NTAPI InjectComplete(void *context, NET_BUFFER_LIST *nbl, BOOLEAN dispatch)
{
    UNREFERENCED_PARAMETER(dispatch);
    if (!NT_SUCCESS(NET_BUFFER_LIST_STATUS(nbl))) InterlockedIncrement64((LONG64 *)&gStats.injectionErrors);
    else InterlockedIncrement64((LONG64 *)&gStats.injected);
    FreeInjection(context);
}

static NTSTATUS WritePacket(const PBDRV_UDP_RECORD *r, ULONG length)
{
    if (length < sizeof(*r) || r->version != PBDRV_UDP_ABI || r->bytes != length ||
        r->payloadBytes > PBDRV_UDP_MAX_PAYLOAD || r->controlBytes > PBDRV_UDP_MAX_CONTROL ||
        r->payloadBytes + r->controlBytes != length - sizeof(*r) ||
        (r->kind == PBDRV_UDP_RECEIVE && r->controlBytes) ||
        (r->family != AF_INET && r->family != AF_INET6) || !r->localPort || !r->remotePort ||
        (r->kind != PBDRV_UDP_RECEIVE && r->kind != PBDRV_UDP_DIRECT)) return STATUS_INVALID_PARAMETER;
    ENDPOINT saved = {0};
    BOOLEAN found = FALSE;
    KIRQL irql;
    KeAcquireSpinLock(&gLock, &irql);
    ENDPOINT *e = gActive ? FindId(r->endpointId) : NULL;
    if (e && e->pid == r->pid && (!e->port || e->port == r->localPort)) { saved = *e; found = TRUE; }
    KeReleaseSpinLock(&gLock, irql);
    if (!found) { InterlockedIncrement64((LONG64 *)&gStats.staleWrites); return STATUS_NOT_FOUND; }
    BOOLEAN receive = r->kind == PBDRV_UDP_RECEIVE;
    ULONG ipBytes = receive ? (r->family == AF_INET ? 20 : 40) : 0;
    ULONG bytes = ipBytes + 8 + r->payloadBytes;
    ULONG allocated = bytes + r->controlBytes + (r->controlBytes ? 15 : 0);
    if (InterlockedAdd(&gInjectBytes, allocated) > MAX_INJECT_BYTES) {
        InterlockedExchangeAdd(&gInjectBytes, -(LONG)allocated);
        InterlockedIncrement64((LONG64 *)&gStats.allocationDrops); return STATUS_QUOTA_EXCEEDED;
    }
    KeAcquireSpinLock(&gLock, &irql);
    if (gInjectCount >= MAX_INJECTIONS) {
        KeReleaseSpinLock(&gLock, irql);
        InterlockedExchangeAdd(&gInjectBytes, -(LONG)allocated);
        InterlockedIncrement64((LONG64 *)&gStats.allocationDrops);
        return STATUS_QUOTA_EXCEEDED;
    }
    if (++gInjectCount == 1) KeClearEvent(&gInjectIdle);
    KeReleaseSpinLock(&gLock, irql);
    INJECTION *i = ExAllocatePool2(POOL_FLAG_NON_PAGED, FIELD_OFFSET(INJECTION, data) + allocated, TAG);
    if (!i) {
        InterlockedIncrement64((LONG64 *)&gStats.allocationDrops);
        InterlockedExchangeAdd(&gInjectBytes, -(LONG)allocated);
        KeAcquireSpinLock(&gLock, &irql);
        if (!--gInjectCount) KeSetEvent(&gInjectIdle, IO_NO_INCREMENT, FALSE);
        KeReleaseSpinLock(&gLock, irql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    i->bytes = allocated;
    (void)PbUdpBuildDatagram(r, i->data);
    i->mdl = IoAllocateMdl(i->data, bytes, FALSE, FALSE, NULL);
    if (!i->mdl) { FreeInjection(i); return STATUS_INSUFFICIENT_RESOURCES; }
    MmBuildMdlForNonPagedPool(i->mdl);
    NTSTATUS status = FwpsAllocateNetBufferAndNetBufferList0(gNblPool, 0, 0, i->mdl, 0, bytes, &i->nbl);
    if (!NT_SUCCESS(status)) { FreeInjection(i); return status; }
    HANDLE inject = r->family == AF_INET ? gInject4 : gInject6;
    if (receive) status = FwpsInjectTransportReceiveAsync0(inject, NULL, NULL, 0, r->family,
        r->compartment, r->interfaceIndex, r->subInterfaceIndex, i->nbl, InjectComplete, i);
    else {
        RtlCopyMemory(i->remote, r->remoteAddress, 16);
        i->send.remoteAddress = i->remote; i->send.remoteScopeId.Value = r->remoteScope;
        if (r->controlBytes) {
            UINT8 *control = (UINT8 *)(((ULONG_PTR)(i->data + bytes) + 15) & ~(ULONG_PTR)15);
            RtlCopyMemory(control, (const UINT8 *)(r + 1) + r->payloadBytes, r->controlBytes);
            i->send.controlData = (WSACMSGHDR *)control; i->send.controlDataLength = r->controlBytes;
        }
        status = FwpsInjectTransportSendAsync0(inject, NULL, saved.handle, 0, &i->send,
            r->family, r->compartment, i->nbl, InjectComplete, i);
    }
    if (!NT_SUCCESS(status)) { InterlockedIncrement64((LONG64 *)&gStats.injectionErrors); FreeInjection(i); }
    return status;
}

NTSTATUS PbUdpWrite(const PBDRV_UDP_RECORD *r, ULONG length)
{
    KIRQL irql;
    KeAcquireSpinLock(&gLock, &irql);
    BOOLEAN acquired = gActive && gWritersReady && ExAcquireRundownProtection(&gWriters);
    KeReleaseSpinLock(&gLock, irql);
    if (!acquired) return STATUS_DEVICE_NOT_READY;
    NTSTATUS status = WritePacket(r, length);
    ExReleaseRundownProtection(&gWriters);
    return status;
}

static NTSTATUS Register(PDEVICE_OBJECT device, HANDLE engine, const GUID *provider, const GUID *sub,
    const GUID *key, const GUID *layer, FWPS_CALLOUT_CLASSIFY_FN1 fn, UINT32 *id, BOOLEAN inspection)
{
    FWPS_CALLOUT1 s = {0}; s.calloutKey = *key; s.classifyFn = fn; s.notifyFn = Notify;
    NTSTATUS status = FwpsCalloutRegister1(device, &s, id);
    if (!NT_SUCCESS(status)) return status;
    FWPM_CALLOUT0 c = {0}; c.calloutKey = *key; c.providerKey = (GUID *)provider;
    c.applicableLayer = *layer; c.displayData.name = L"ProxyBridge UDP packet channel";
    status = FwpmCalloutAdd0(engine, &c, NULL, NULL); if (!NT_SUCCESS(status)) return status;
    FWPM_FILTER0 f = {0}; f.layerKey = *layer; f.subLayerKey = *sub; f.providerKey = (GUID *)provider;
    f.displayData.name = c.displayData.name; f.weight.type = FWP_EMPTY;
    f.action.type = inspection ? FWP_ACTION_CALLOUT_INSPECTION : FWP_ACTION_CALLOUT_UNKNOWN;
    f.action.calloutKey = *key;
    return FwpmFilterAdd0(engine, &f, NULL, NULL);
}

NTSTATUS PbUdpStart(PDEVICE_OBJECT device, HANDLE engine, const GUID *provider, const GUID *sub)
{
    gStarted = TRUE;
    ExInitializeRundownProtection(&gWriters);
    gWritersReady = TRUE;
    NET_BUFFER_LIST_POOL_PARAMETERS pool = {0};
    pool.Header.Type = NDIS_OBJECT_TYPE_DEFAULT; pool.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    pool.Header.Size = sizeof(pool); pool.fAllocateNetBuffer = TRUE; pool.PoolTag = TAG;
    gNblPool = NdisAllocateNetBufferListPool(NULL, &pool);
    if (!gNblPool) return STATUS_INSUFFICIENT_RESOURCES;
    NTSTATUS status = FwpsInjectionHandleCreate0(AF_INET, FWPS_INJECTION_TYPE_TRANSPORT, &gInject4);
    if (!NT_SUCCESS(status)) return status;
    status = FwpsInjectionHandleCreate0(AF_INET6, FWPS_INJECTION_TYPE_TRANSPORT, &gInject6);
    if (!NT_SUCCESS(status)) return status;
    const GUID *keys[] = {&UDP_AUTH4,&UDP_AUTH6,&UDP_DATA4,&UDP_DATA6,&UDP_CLOSE4,&UDP_CLOSE6};
    const GUID *layers[] = {&FWPM_LAYER_ALE_AUTH_CONNECT_V4,&FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        &FWPM_LAYER_DATAGRAM_DATA_V4,&FWPM_LAYER_DATAGRAM_DATA_V6,&FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V4,&FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V6};
    FWPS_CALLOUT_CLASSIFY_FN1 fns[] = {Authorize,Authorize,Datagram,Datagram,Closed,Closed};
    for (ULONG n = 0; n < RTL_NUMBER_OF(keys); ++n) {
        status = Register(device, engine, provider, sub, keys[n], layers[n], fns[n], &gCallouts[n], n >= 4);
        if (!NT_SUCCESS(status)) return status;
    }
    WdfIoQueueStart(gReads);
    KIRQL irql; KeAcquireSpinLock(&gLock, &irql); gActive = TRUE; KeReleaseSpinLock(&gLock, irql);
    return STATUS_SUCCESS;
}

NTSTATUS PbUdpStop(void)
{
    if (!gInitialized || !gStarted) return STATUS_SUCCESS;
    KIRQL irql; KeAcquireSpinLock(&gLock, &irql); gActive = FALSE; KeReleaseSpinLock(&gLock, irql);
    if (gWritersReady) { ExWaitForRundownProtectionRelease(&gWriters); gWritersReady = FALSE; }
    NTSTATUS result = STATUS_SUCCESS;
    for (ULONG n = 0; n < RTL_NUMBER_OF(gCallouts); ++n) if (gCallouts[n]) {
        NTSTATUS status = FwpsCalloutUnregisterById0(gCallouts[n]);
        if (NT_SUCCESS(status) || status == STATUS_FWP_CALLOUT_NOT_FOUND) gCallouts[n] = 0;
        else if (NT_SUCCESS(result)) result = status;
    }
    if (!NT_SUCCESS(result)) return result;
    if (gReads) WdfIoQueuePurgeSynchronously(gReads);
    if (gWork) WdfWorkItemFlush(gWork);
    KeWaitForSingleObject(&gInjectIdle, Executive, KernelMode, FALSE, NULL);
    if (gInject4) { FwpsInjectionHandleDestroy0(gInject4); gInject4 = NULL; }
    if (gInject6) { FwpsInjectionHandleDestroy0(gInject6); gInject6 = NULL; }
    if (gNblPool) { NdisFreeNetBufferListPool(gNblPool); gNblPool = NULL; }
    PbUdpReset();
    gStarted = FALSE;
    return STATUS_SUCCESS;
}
void PbUdpReset(void)
{
    KIRQL irql; KeAcquireSpinLock(&gLock, &irql);
    while (!IsListEmpty(&gPackets)) ExFreePoolWithTag(CONTAINING_RECORD(RemoveHeadList(&gPackets), PACKET, link), TAG);
    for (ULONG n = 0; n < BUCKETS; ++n)
        while (!IsListEmpty(&gEndpoints[n])) ExFreePoolWithTag(CONTAINING_RECORD(RemoveHeadList(&gEndpoints[n]), ENDPOINT, link), TAG);
    for (ULONG n = 0; n < BUCKETS; ++n) InitializeListHead(&gById[n]);
    gQueueBytes = gQueueCount = gEndpointCount = 0; gWorkQueued = FALSE;
    KeReleaseSpinLock(&gLock, irql);
}
void PbUdpStats(PBDRV_UDP_STATS *stats)
{
    // Counters are aligned in the module even though the wire layout is packed.
    LONG64 *out = (LONG64 *)stats, *in = (LONG64 *)&gStats;
    for (ULONG n = 0; n < sizeof(gStats) / sizeof(LONG64); ++n)
        out[n] = InterlockedCompareExchange64(&in[n], 0, 0);
}
