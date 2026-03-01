# Building and Using the OFI/libfabric Transport

NNG includes an experimental transport for [OFI/libfabric](https://ofiwg.github.io/libfabric/)
(scheme `ofi://`).  It lets ordinary NNG programs communicate over any
fabric that libfabric supports: Ethernet sockets (loopback or LAN),
InfiniBand, RoCE, HPE Slingshot (CXI), AWS EFA, Intel Omni-Path, and
more — with no application-level code changes beyond the address scheme.

> [!IMPORTANT]
> This transport is **EXPERIMENTAL**.  APIs, wire format, and CMake
> options may change before it graduates to stable status.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Building NNG with OFI Support](#building-nng-with-ofi-support)
3. [Provider Selection](#provider-selection)
4. [Quick-start: loopback test](#quick-start-loopback-test)
5. [Playbook: Building a Service with libfabric Endpoints](#playbook-building-a-service-with-libfabric-endpoints)
6. [Address Format](#address-format)
7. [Wire Protocol Reference](#wire-protocol-reference)
8. [Architecture Notes](#architecture-notes)
9. [Performance Considerations and Known Limitations](#performance-considerations-and-known-limitations)
10. [Production Deployment — HPE Slingshot (CXI)](#production-deployment--hpe-slingshot-cxi)
11. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### libfabric

libfabric (package name `libfabric` or `libfabric-dev`) must be
installed **before** running CMake.  NNG uses `pkg-config` to locate it.

| Distribution | Package |
|---|---|
| Ubuntu / Debian | `sudo apt install libfabric-dev` |
| Fedora / RHEL | `sudo dnf install libfabric-devel` |
| macOS (Homebrew) | `brew install libfabric` |
| Spack | `spack install libfabric` |
| From source | [github.com/ofiwg/libfabric](https://github.com/ofiwg/libfabric) |

Verify the installation:

```sh
pkg-config --modversion libfabric    # should print a version, e.g. 2.4.0
fi_info --list                        # lists available providers
```

NNG requires libfabric ≥ 1.11 (`FI_VERSION(1,11)` API).

### Hardware

The `sockets` provider ships with every libfabric installation and needs
no special hardware.  It gives you `ofi://` connectivity over regular
TCP/IP sockets — useful for development and testing on any machine.

For real RDMA (zero-copy, kernel bypass) you need the matching provider
and hardware:

| Provider | Hardware |
|---|---|
| `verbs` | InfiniBand, RoCE NICs |
| `cxi` | HPE Slingshot 200G NIC |
| `efa` | AWS Elastic Fabric Adapter |
| `psm3` | Intel Omni-Path |
| `tcp` | RDMA over TCP (software, no special HW) |

---

## Building NNG with OFI Support

The OFI transport is **off by default**.  Enable it with the CMake
option `NNG_TRANSPORT_OFI=ON`:

```sh
git clone https://github.com/nanomsg/nng.git && cd nng
mkdir build && cd build

cmake -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DNNG_TRANSPORT_OFI=ON \
      ..

ninja
ctest -R nng.sp.transport.ofi --output-on-failure
```

Expected test output:

```
Test ofi-scheme-recognized: SUCCESS
Test ofi-listen:             SUCCESS
Test ofi-connect:            SUCCESS
Test ofi-exchange:           SUCCESS
```

### Key CMake Options

| Option | Default | Description |
|---|---|---|
| `NNG_TRANSPORT_OFI` | `OFF` | Enable the OFI transport |
| `NNG_OFI_PROVIDER` | _(auto)_ | Lock in a provider at compile time (e.g. `cxi`, `tcp`, `sockets`) |
| `NNG_SANITIZER` | _(none)_ | `address` or `thread` for debug builds |

Setting `NNG_OFI_PROVIDER` bakes the name into the library as
`NNG_OFI_DEFAULT_PROVIDER`.  You can still override it at runtime
(see [Provider Selection](#provider-selection)).

#### Example: build locked to the CXI provider

```sh
cmake -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DNNG_TRANSPORT_OFI=ON \
      -DNNG_OFI_PROVIDER=cxi \
      ..
```

---

## Provider Selection

The transport selects its libfabric provider at process startup using
the following priority order (highest to lowest):

1. **Runtime env var** `NNG_OFI_PROVIDER` — set before launching the
   process: `NNG_OFI_PROVIDER=verbs ./my_service`
2. **Compile-time default** `NNG_OFI_PROVIDER` CMake option — baked in
   at build time.
3. **Auto-detect** — libfabric picks the best available provider for the
   requested capabilities (`FI_EP_MSG | FI_MSG`).

On startup, NNG logs the chosen provider at `INFO` level:

```
[NNG-OFI] Initialized provider: sockets
```

If no suitable provider is found, `ofi://` is silently unavailable
(dial/listen return `NNG_ENOTSUP`).  Enable NNG logging to see why:

```c
nng_log_set_level(NNG_LOG_DEBUG);
nng_log_set_logger(nng_stderr_logger);
```

---

## Quick-start: Loopback Test

This example sends a message from one process to another on the same
machine using the `sockets` provider (no RDMA hardware needed).

### Server

```c
#include <nng/nng.h>
#include <nng/protocol/pair1/pair.h>
#include <stdio.h>

int main(void) {
    nng_socket  sock;
    nng_listener l;
    char        *buf;
    size_t       sz;

    nng_pair1_open(&sock);
    nng_listen(sock, "ofi://127.0.0.1:5555", &l, 0);
    printf("Listening on ofi://127.0.0.1:5555\n");

    for (;;) {
        nng_recv(sock, &buf, &sz, NNG_FLAG_ALLOC);
        printf("Received: %.*s\n", (int) sz, buf);
        nng_free(buf, sz);

        const char *reply = "pong";
        nng_send(sock, (void *) reply, strlen(reply) + 1, 0);
    }

    nng_socket_close(sock);
}
```

### Client

```c
#include <nng/nng.h>
#include <nng/protocol/pair1/pair.h>
#include <stdio.h>

int main(void) {
    nng_socket sock;
    char      *buf;
    size_t     sz;

    nng_pair1_open(&sock);
    nng_dial(sock, "ofi://127.0.0.1:5555", NULL, 0);

    nng_send(sock, "ping", 5, 0);
    nng_recv(sock, &buf, &sz, NNG_FLAG_ALLOC);
    printf("Reply: %s\n", buf);
    nng_free(buf, sz);

    nng_socket_close(sock);
}
```

Compile and run:

```sh
cc -o server server.c -lnng
cc -o client client.c -lnng

# Terminal 1
NNG_OFI_PROVIDER=sockets ./server

# Terminal 2
NNG_OFI_PROVIDER=sockets ./client
```

---

## Playbook: Building a Service with libfabric Endpoints

This section is a step-by-step guide for building a production-ready
request-reply service that uses the OFI transport.  The patterns apply
to any NNG protocol (pub/sub, push/pull, etc.); req/rep is shown because
it is the most common RPC pattern.

### Step 1 — Choose Your Protocol and Address

Pick the NNG scalability protocol that fits your communication pattern:

| Pattern | Protocol | Header |
|---|---|---|
| Request / reply | `req0` / `rep0` | `<nng/protocol/reqrep0/req.h>` |
| Publish / subscribe | `pub0` / `sub0` | `<nng/protocol/pubsub0/pub.h>` |
| Push pipeline | `push0` / `pull0` | `<nng/protocol/pipeline0/push.h>` |
| Fan-out / survey | `surveyor0` / `respondent0` | `<nng/protocol/survey0/surveyor.h>` |
| Bidirectional | `pair1` | `<nng/protocol/pair1/pair.h>` |

Pick an address.  For local testing use `127.0.0.1`.  For a real
cluster use the interface IP the fabric is bound to (e.g. the IP of the
CXI or IB port):

```
ofi://10.200.0.5:7000      # IPv4 fabric IP, static port
ofi://[fe80::1%cxi0]:7000  # IPv6 link-local with interface scope
```

### Step 2 — Initialize Logging

Enable NNG logging early so transport problems are visible:

```c
nng_log_set_level(NNG_LOG_INFO);      // or NNG_LOG_DEBUG for more detail
nng_log_set_logger(nng_stderr_logger);
```

In production, use `nng_log_set_facility` and route to syslog instead.

### Step 3 — Create and Configure the Socket

```c
nng_socket srv;
nng_rep0_open(&srv);

// Tuning (adjust to workload):
nng_socket_set_ms(srv, NNG_OPT_RECVTIMEO, 5000);   // 5 s recv timeout
nng_socket_set_ms(srv, NNG_OPT_SENDTIMEO, 5000);   // 5 s send timeout
nng_socket_set_int(srv, NNG_OPT_RECVBUF,  128);    // recv queue depth
nng_socket_set_int(srv, NNG_OPT_SENDBUF,  128);    // send queue depth
// Max message size — must be ≤ OFI_BOUNCE_SZ (default 1 MiB) minus 8 bytes.
nng_socket_set_size(srv, NNG_OPT_RECVMAXSZ, 512 * 1024);
```

> [!IMPORTANT]
> The OFI transport uses a fixed 1 MiB bounce buffer per pipe.
> `NNG_OPT_RECVMAXSZ` should be set to ≤ 1 MiB − 8 bytes (i.e. at
> most `1048568`).  Messages larger than the bounce buffer are rejected
> with `NNG_EMSGSIZE`.

### Step 4 — Start Listening (Server Side)

```c
nng_listener l;
int rv = nng_listen(srv, "ofi://0.0.0.0:7000", &l, 0);
if (rv != NNG_OK) {
    fprintf(stderr, "listen failed: %s\n", nng_strerror(rv));
    exit(1);
}

// If you bound port 0, retrieve the actual port:
nng_url *url;
nng_listener_get_url(l, &url);
printf("Listening on %s\n", nng_url_rawurl(url));
nng_url_free(url);
```

Using port `0` lets the OS assign an ephemeral port; `nng_listener_get_url`
returns the URL with the real port filled in.

### Step 5 — Dial (Client Side)

```c
nng_socket cli;
nng_req0_open(&cli);

nng_socket_set_ms(cli, NNG_OPT_RECONNMINT, 100);   // min reconnect 100 ms
nng_socket_set_ms(cli, NNG_OPT_RECONNMAXT, 5000);  // max reconnect 5 s

int rv = nng_dial(cli, "ofi://10.200.0.5:7000", NULL, 0);
if (rv != NNG_OK) {
    fprintf(stderr, "dial failed: %s\n", nng_strerror(rv));
    exit(1);
}
```

NNG automatically reconnects after a lost connection.  The dialer
retries with exponential back-off between `RECONNMINT` and `RECONNMAXT`.

### Step 6 — Send and Receive Messages

#### Synchronous (simple)

```c
// Client: send request, wait for reply.
nng_send(cli, request_buf, request_sz, 0);
nng_recv(cli, &reply_buf, &reply_sz, NNG_FLAG_ALLOC);
// ...use reply...
nng_free(reply_buf, reply_sz);

// Server: receive request, send reply.
nng_recv(srv, &req_buf, &req_sz, NNG_FLAG_ALLOC);
// ...process...
nng_send(srv, reply_buf, reply_sz, 0);
nng_free(req_buf, req_sz);
```

#### Asynchronous (zero-copy, preferred for high throughput)

```c
nng_aio *saio, *raio;
nng_msg *msg;

nng_aio_alloc(&saio, send_callback, ctx);
nng_aio_alloc(&raio, recv_callback, ctx);

// Start a non-blocking recv:
nng_recv_aio(srv, raio);

// In the recv callback — build a reply and send it:
void recv_callback(void *arg) {
    ctx_t   *ctx = arg;
    nng_msg *req = nng_aio_get_msg(ctx->raio);
    // ...process req...

    nng_msg *rep;
    nng_msg_alloc(&rep, 0);
    nng_msg_append(rep, reply_bytes, reply_sz);
    nng_aio_set_msg(ctx->saio, rep);
    nng_send_aio(ctx->sock, ctx->saio);

    nng_msg_free(req);
    nng_recv_aio(ctx->sock, ctx->raio);  // re-arm
}
```

### Step 7 — Graceful Shutdown

```c
// Stop accepting new connections, drain in-flight messages.
nng_socket_close(srv);
nng_socket_close(cli);

// Optional: release all NNG resources (useful for leak-checking).
nng_fini();
```

`nng_socket_close` waits for all pending AIOs to complete or time out,
then tears down every pipe belonging to the socket.

### Step 8 — Selecting the Provider at Runtime

Set `NNG_OFI_PROVIDER` in the environment before launching the binary:

```sh
# Local test — no RDMA hardware required:
NNG_OFI_PROVIDER=sockets ./my_service

# HPE Slingshot:
NNG_OFI_PROVIDER=cxi ./my_service

# InfiniBand / RoCE:
NNG_OFI_PROVIDER=verbs ./my_service

# Auto-detect (default when neither env var nor compile-time default is set):
./my_service
```

The chosen provider is logged at startup:

```
[NNG-OFI] Initialized provider: cxi
```

---

## Address Format

```
ofi://<host>:<port>
ofi://[<ipv6>]:<port>
```

| Component | Notes |
|---|---|
| `host` | Hostname, IPv4 address, or IPv6 address in brackets |
| `port` | TCP/IP port number; use `0` to let the OS assign one |

Examples:

```
ofi://127.0.0.1:5555
ofi://node42.cluster.local:7000
ofi://[::1]:5555
ofi://0.0.0.0:0        # listen on all interfaces, OS-assigned port
```

> [!NOTE]
> The host field is passed directly to `fi_getinfo`.  For providers
> that use non-IP addressing (e.g. `psm3`) the address may need to be
> the fabric-specific node identifier rather than an IP address.
> Check your provider documentation.

---

## Wire Protocol Reference

Each connection begins with a mutual **SP negotiation handshake** before
data messages flow.  The format is identical to the NNG TCP transport.

### Negotiation Frame (8 bytes, each direction)

```
Offset  Len  Value
------  ---  -----
0       1    0x00        (reserved)
1       1    0x53 'S'
2       1    0x50 'P'
3       1    0x00        (reserved)
4-5     2    Protocol ID (big-endian, e.g. 0x0031 for pair1 SP)
6       1    0x00        (version, reserved)
7       1    0x00        (options, reserved)
```

The connection is rejected if the magic bytes (`\x00SP\x00`) do not match.

### Data Frame

Every NNG message is prefixed with a fixed 8-byte length header before
being written to the bounce buffer:

```
Offset  Len  Value
------  ---  -----
0-7     8    Total message length (header+body), big-endian uint64
8+      N    NNG message content (header bytes first, then body bytes)
```

The receiver reads the 8-byte prefix from the bounce buffer directly
(not from `cqe.len`, which some providers leave at zero) to determine
how many subsequent bytes to copy into the NNG message.

---

## Architecture Notes

Understanding the internals helps when debugging or extending the transport.

### Component Map

```
nng_socket
  └─ ofi_ep (one per dialer or listener)
       ├─ fid_pep        passive endpoint  [listener only]
       ├─ fid_eq         CM event queue    [shared EQ thread]
       └─ ofi_pipe (one per active connection)
            ├─ fid_ep    active endpoint (FI_EP_MSG, reliable connected)
            ├─ fid_cq    TX completion queue
            ├─ fid_cq    RX completion queue
            ├─ fid_mr    registered TX bounce buffer (1 MiB)
            ├─ fid_mr    registered RX bounce buffer (1 MiB)
            └─ cq_thr    CQ polling thread
```

### Thread Model

| Thread | Purpose | Lifetime |
|---|---|---|
| **EQ thread** (1/endpoint) | Polls `fi_eq_sread` for `FI_CONNREQ` / `FI_CONNECTED` / `FI_SHUTDOWN` events.  On `FI_CONNREQ`, accepts the connection and creates an `ofi_pipe`.  On `FI_CONNECTED` (dialer), attaches the pipe. | Created in `l_bind` / `d_connect`, joined in `l_stop` / `d_stop` |
| **CQ thread** (1/pipe) | Polls `fi_cq_read` on the pipe's TX and RX CQs at ~1 kHz.  Drives the SP negotiation handshake, then delivers data messages to queued recv AIOs. | Started by `ofi_pipe_alloc`, stopped by `p_stop` |
| **NNG task threads** | Dispatch AIO callbacks (send/recv completions) to user code. | Managed by NNG core |

### Connection Lifecycle

```
Dialer                              Listener
------                              --------
nng_dial()
  → ofi_dialer_connect()
      fi_connect(active_ep, ...)
      [waits on EQ]
                                    [FI_CONNREQ on pep EQ]
                                    fi_accept(new_ep, ...)
                                    ofi_pipe_alloc(listener)
                                      pre-post RX
                                      nego TX queued
                                      start CQ thread
[FI_CONNECTED on active_ep EQ]
ofi_pipe_alloc(dialer)
  pre-post RX
  nego TX queued
  start CQ thread

[CQ thread]                         [CQ thread]
  TX CQ: nego TX drains (no AIO)      TX CQ: nego TX drains (no AIO)
  RX CQ: nego bytes arrive            RX CQ: nego bytes arrive
  ofi_pipe_nego_complete()            ofi_pipe_nego_complete()
    → deliver pipe via AIO              → deliver pipe via AIO
```

### Message Flow (data phase)

```
nng_send(sock, msg)
  ofi_pipe_send()
    copy [8-byte len][header][body] into tx_buf
    fi_sendmsg() → TX CQ completion pending

[CQ thread]
  fi_cq_read(tx_cq)
    → nni_aio_finish_sync(send_aio)  // signals sender

nng_recv(sock, &buf)
  ofi_pipe_recv()
    enqueue recv AIO in p->recvq

[CQ thread]
  fi_cq_read(rx_cq)
    read msglen from rx_buf[0..7]
    alloc nni_msg, copy body from rx_buf[8..]
    dequeue recv AIO from p->recvq
    nni_aio_finish_sync(recv_aio)    // signals receiver
    re-post RX buffer
```

---

## Performance Considerations and Known Limitations

### Current Limitations

| Limitation | Impact | Future Direction |
|---|---|---|
| **1 MiB bounce buffer per pipe** | Messages larger than ~1 MiB − 8 bytes are rejected with `NNG_EMSGSIZE`. | Increase `OFI_BOUNCE_SZ` or implement scatter-gather across multiple MRs. |
| **1 ms busy-poll interval** | CPU spin at ~1 kHz per pipe.  High-connection-count deployments will see elevated CPU usage. | Replace with `fi_cq_sread` (blocking wait with timeout) or an fd-based poller. |
| **One in-flight send per pipe** | Only one `fi_sendmsg` per pipe at a time; the next send waits for the TX CQ completion. | Implement a deeper TX pipeline with multiple in-flight sends. |
| **One in-flight receive per pipe** | The single pre-posted RX buffer is re-posted after each message delivery. | Pre-post multiple receive buffers. |
| **No RDMA zero-copy** | Data always passes through the registered bounce buffers (software copy). | Support `NNG_FLAG_ZEROCOPY` with user-space MR registration. |

### Tuning Recommendations

- Set `NNG_OFT_PROVIDER` to a specific provider rather than relying on
  auto-detect to avoid surprising provider choices.
- Keep `NNG_OPT_RECVMAXSZ` well below 1 MiB so that oversized messages
  fail fast rather than silently truncating.
- On many RDMA fabrics, page-aligning the 1 MiB bounce buffers
  (`posix_memalign`) improves memory registration performance.  This is
  a future improvement to `OFI_BOUNCE_SZ` allocation in `ofi_pipe_alloc`.

---

## Production Deployment — HPE Slingshot (CXI)

HPE Slingshot uses the `cxi` libfabric provider.  Key points:

### Environment setup

```sh
# Ensure the CXI kernel module is loaded.
lsmod | grep cxi_core

# Verify the provider is available:
fi_info -p cxi

# Check fabric interface names (typically cxi0, cxi1, …):
ls /dev/cxi*
```

### Build configuration

```sh
cmake -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DNNG_TRANSPORT_OFI=ON \
      -DNNG_OFI_PROVIDER=cxi \
      ..
ninja
```

### Job launcher integration (Slurm/PMI)

When running under Slurm with the CXI plugin, the fabric interface is
selected by the MPI launcher.  For NNG-only services that don't use MPI,
pass the Slingshot IP address explicitly:

```sh
# Determine the HSN (high-speed network) IP of this node:
HSN_IP=$(ip -4 -o addr show cxi0 | awk '{print $4}' | cut -d/ -f1)

# Start the service bound to the HSN:
NNG_OFI_PROVIDER=cxi ./my_service "ofi://${HSN_IP}:7000"
```

### Resilience

CXI supports hardware-level retransmission so transient link errors are
transparent to the application.  NNG's built-in reconnection handles the
case where a service restarts:

```c
nng_socket_set_ms(sock, NNG_OPT_RECONNMINT, 500);
nng_socket_set_ms(sock, NNG_OPT_RECONNMAXT, 30000);
```

### Security

CXI does not encrypt in hardware.  For multi-tenant environments combine
the OFI transport with NNG's TLS transport (`tls+tcp://`) or protect
the channel at the network level (VPN, IPsec).

---

## Troubleshooting

### `nng_dial` / `nng_listen` returns `NNG_ENOTSUP`

libfabric found no suitable provider.  Enable INFO logging to see the
`fi_getinfo` error, then verify:

```sh
fi_info --caps msg --ep-type msg   # must list at least one provider
pkg-config --modversion libfabric  # must be ≥ 1.11
```

### `nng_dial` returns `NNG_ETRANERR`

The transport error didn't map to a known errno.  Enable DEBUG logging
and inspect the `prov_errno` from the EQ or CQ error entries in the
`[NNG-OFI]` log lines.

Common causes:
- Wrong provider selected (e.g. `cxi` on a non-Slingshot machine).
- Firewall blocking the port.
- Dialing to port `0` (the listener's `nng_listener_get_url` must be
  called after `nng_listen` to retrieve the actual bound port).

### Socket close hangs

If `nng_socket_close` blocks indefinitely, a CQ thread has not exited.
Possible causes:
- A recv or send AIO was not cancelled before pipe teardown (NNG bug).
- The CQ thread crashed without clearing `cq_running`.

Enable ASAN (`-DNNG_SANITIZER=address`) to detect memory errors and
use macOS `sample <pid>` or Linux `pstack <pid>` to capture thread
stacks.

### Messages are silently discarded

If the receiver queue is empty when a message arrives on the RX CQ, the
message is dropped.  Ensure that a recv AIO is always re-armed
immediately after receiving a message.  Check `nng_stat_get_uint64` on
the `rx_drop` statistic.

### Provider selection surprises (`fi_info` picks unexpected provider)

Pin the provider:

```sh
NNG_OFI_PROVIDER=sockets ./my_service    # force sockets for local test
```

or at build time:

```sh
cmake ... -DNNG_OFI_PROVIDER=sockets ...
```

### ASAN false positives from libfabric

Some libfabric providers deliberately use uninitialized memory in fast
paths.  Suppress them with a `LSAN_OPTIONS` suppression file:

```sh
ASAN_OPTIONS=detect_leaks=0 ./my_service    # disable leak checker only
```
