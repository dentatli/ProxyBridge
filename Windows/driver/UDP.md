# Experimental UDP packet channel

This branch replaces the UDP source-to-last-destination map with a versioned
datagram channel. **Kernel runtime validation and performance acceptance are
still required.** A successful build is not evidence of working WFP delivery.

TCP retains its connect-redirect path. UDP authorization records the owning
transport endpoint and image; outbound DATAGRAM_DATA supplies the actual local
and remote addresses/ports with each payload. ALE_ENDPOINT_CLOSURE invalidates
the endpoint ID. IDs do not repeat during a driver load. No kernel pointer or
transport endpoint handle crosses the wire.

Core and SYS must be updated together. Core checks UDP_CAPS before enabling
capture; SET_CONFIG requires udpAbi=1, so an old Core cannot silently enable
this backend. There is one physical IOCTL definition under driver/src; the Core
header forwards to it. The old QUERY_UDP contract is not a fallback.

## Transport and ownership

- A manual KMDF queue owns pending direct-output UDP_READ requests and their
  cancellation. A coalesced work item returns immediately available records
  without a batching timer. Records include an 84-byte header, payload, then
  bounded outbound ancillary data.
- Core uses one IOCP worker with asynchronous ConnectEx, SOCKS negotiation,
  authentication, DNS for domain BND replies, UDP receives/sends and device I/O.
  No blocking proxy handshake runs on the packet loop.
- Association identity includes endpoint ID, actual local family/address/port,
  compartment and proxy configuration. This distinguishes multiple addresses
  used by one wildcard-bound socket. Multiple destinations with the same local
  identity share an association. Separate clients never share it.
- Replies are matched within the receiving association, not by a global latest
  client heuristic. Source metadata and ancillary bytes stay attached to each
  original datagram. Direct decisions use transport-send injection; proxy
  replies use transport-receive injection with constructed IPv4/IPv6 headers.
- Writer rundown and injection completion drain before handles/pools disappear.
  Core cancels and drains its completions before closing the controller handle.
  Queue, metadata, allocation, stale-write and injection errors are counted;
  the event drain reports changes in kernel error counters.

## Bounds and current limits

| Resource | Bound |
| --- | --- |
| Kernel tracked endpoints | 4096 |
| Kernel queued records | 2048 and 2 MiB record bytes |
| Kernel injections in flight | 1024 and 2 MiB packet/control bytes |
| Core associations | 512 |
| Destinations per association | 128 |
| Core process-name cache | 4096 endpoints |
| Queued handshake traffic | 2 MiB total, 128 KiB per association |
| Core outstanding I/O | 8192 operations, 64 MiB including operation headers/buffers |
| Outbound ancillary bytes per datagram | 1024 |

These are bounded starting values, not tuned performance claims. Allocation
overheads, endpoint structures, MDLs/NBLs and OS socket buffers also consume
memory. A full-size pending UDP receive uses a 65535-byte buffer per association.
Idle associations expire after five minutes; handshakes after five seconds.
The proxy TCP transport retains the existing IPv4 resolved-address model; UDP
BND relay addresses support IPv4, IPv6 and asynchronously resolved names.

SOCKS FRAG!=0 and domain-form UDP response headers are rejected/counted; UDP
fragment reassembly is not implemented. SOCKS encapsulation reduces the largest
accepted proxied payload to 65497 bytes for IPv4 destinations and 65485 for
IPv6 destinations. Jumbograms and UDP segmentation offload aggregates are not
accepted as ordinary datagrams. Broader compatibility requires explicit checks.

Overflow during active capture drops/counts traffic instead of guessing an
owner or sending proxy/block traffic direct. The existing explicit Stop and
owner-cleanup lifecycle disables WFP filtering; this change does not add a
persistent firewall after Core exit. Fail-closed behavior after a Core crash
is a separate product policy/lifecycle decision and is not claimed here.

## Validation status

Physical Windows 11 testing on 2026-10-22 found that a freshly allocated
loopback reply submitted to transport receive completed with
`STATUS_DATA_NOT_ACCEPTED` (0xC000021B). Replies with both addresses in software
loopback now use network send injection, preserving the original source tuple;
other replies retain transport receive. Separate network injection handles are
checked for self-injection and drained/destroyed on teardown. Last injection
failure status, stage and routing metadata are exposed with the counters.

The physical trials passed 12/12 IPv4/IPv6 socket/bind variants and the
two-clients/one-origin isolation check. The final 1.1.0.0 package additionally
passed 39/39 Core correctness cases, with 42/42 direct and 42/42 explicit SOCKS
controls: zero/1/1200/8192/65000-byte payloads, software loopback and the target's
own LAN address, two destinations on one socket, delayed replies across endpoint
reuse, UDP DIRECT/BLOCK, and isolation of a stalled proxy handshake. A healthy
route on the same socket continued before and after the other route's timeout.
The stalled packet was not sent directly. Normal and fault probes stopped
without remaining helper threads or forced cleanup.

The standard TestLab CLI lifecycle/route/payload/source gates also confirmed
13,536/13,536 proxied IPv4 echoes across repeated OFF/PROXY series, one/two
streams and shared/distinct origins, with observed CPU/RAM coverage and verified
driver detachment. Those tests used an explicitly identified TestLab CLI with
unbuffered output and main-thread shutdown, identical for both Core versions.
They measured local paced echo traffic, not maximum throughput. The old Core
returned the wrong source endpoint and mixed clients; its timings are not a
correctness-equivalent performance baseline. No speed advantage is claimed.

The final native product CLI also passed three ConPTY startup/graceful-stop
cycles and 1,536/1,536 additional two-stream echoes with matching package 1.1.0.0.
Its startup message is explicitly flushed; main owns Stop and retains the DLL
until process exit instead of racing the console-control handler. The earlier
version comparison still uses identical instrumented CLIs for comparability.

Release builds, native driver analysis, standalone INF verification and catalog/
signature checks passed. The WDK package-verifier task was unavailable; this is
not current HLK/DVL certification. Physical install/restart and rollback checked
the loaded SYS hash, PnP version and final baseline Stopped/Disabled state.
Package 1.1.0.0 has the same executable sections as the benchmarked driver;
its INF/PE version distinguishes it from the old package in DriverStore. Use a
distinct package version when changing a binary; do not reuse a published INF
identity for different SYS files.

External network paths, multiple local addresses on a single endpoint,
long-duration/high-load behavior, power transitions, kernel pool/handle trends
and owner-crash policy remain outside these local gates. Existing owner cleanup
disables filtering after Core exit; persistent fail-closed behavior is not added.
TestLab also reproduced an existing TCP DIRECT-to-proxy route defect in both
versions. It was not changed by this UDP work and remains unresolved. Full
product acceptance must account for these limitations.
