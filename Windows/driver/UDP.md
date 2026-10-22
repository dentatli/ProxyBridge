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

Release Core/CLI and KMDF compile/link, standalone INF verification and native
driver code analysis are performed in the TestLab checkout. Lab-only probes
exercise actual Core IOCP/SOCKS code through a simulated device seam and the
actual packet builder against independent checksum calculations. They are not
installed product tests and do not validate WFP metadata, injection, PnP/power
transitions, kernel teardown or end-to-end application traffic.

Before acceptance, run a fresh bounded physical-target trial with a matching
signed package and recovery baseline: IPv4/IPv6, implicit/wildcard/concrete bind,
connected/sendto, two clients/one remote, one client/multiple remotes and local
addresses, endpoint reuse, direct/block rules, owner stop/crash and cancellation.
Then measure loss, latency tails, throughput, CPU, memory and handles under load.
Do not infer a performance improvement from the architecture or isolated probes.
