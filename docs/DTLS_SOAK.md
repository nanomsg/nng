# Long-running DTLS validation

`src/sp/transport/dtls/dtls_soak.py` drives long-lived, mutually authenticated
NNG request/reply peers through a local UDP fault proxy. It runs on macOS and
Linux with Python 3.9 or newer; macOS also needs `lsof` (provided by the OS).
The C peer is portable and builds with the existing test targets.
The soak is opt-in and is not registered as a routine CTest test.

## Build and run

Use build trees configured with `NNG_TESTS=ON`, `NNG_ENABLE_TLS=ON`,
`NNG_ENABLE_STATS=ON`, and `NNG_TRANSPORT_DTLS=ON`.
Configure each tree for its TLS engine as described in [BUILD_TLS.md](BUILD_TLS.md).
For example, with the three existing build trees:

```sh
cmake --build build.mbed --target dtls_soak_peer
cmake --build build.wolf591 --target dtls_soak_peer
cmake --build build.openssl13 --target dtls_soak_peer

python3 src/sp/transport/dtls/dtls_soak.py \
  --peer mbed=build.mbed/src/sp/transport/dtls/dtls_soak_peer \
  --peer wolf=build.wolf591/src/sp/transport/dtls/dtls_soak_peer \
  --peer openssl=build.openssl13/src/sp/transport/dtls/dtls_soak_peer \
  --duration 14400 --output .context/dtls-soak-four-hours
```

The default duration is four hours; use `--duration 43200` for an overnight run.
The output directory must be new. Add `--keep-awake` on macOS to prevent idle
sleep for the lifetime of the runner. Run it from a persistent terminal or
launch it with `subprocess.Popen(..., start_new_session=True)` and redirect its
standard input/output; closing an ordinary interactive shell can stop its jobs.
All network traffic stays on IPv4 loopback and uses the repository's test
certificates. No privileged network configuration or packet filter is needed.

The runner probes the compiled DTLS capabilities before starting the matrix.
Mbed TLS supports DTLS 1.2; appropriately built wolfSSL and OpenSSL also support
DTLS 1.3. With all three engines and DTLS 1.3 enabled, the default matrix has
13 client/server/version combinations, each with a persistent server and client
process. `--self-only` omits cross-engine combinations. A single `--peer` is also
useful for sanitizer builds; `--version 12` or `--version 13` selects one
protocol version.

## Workload

Each client process keeps two request/reply sockets open and continuously
recreates a third socket after 20 request attempts. Successful replies must match
the entire request, including its sequence and generated payload, byte for byte.
Peers use two NNG task threads and one polling, expiry, and resolver thread,
exercising the supported minimum callback pool during concurrent reconnects.
Payload sizes rotate through 64, 256, 1024, and 4096 bytes. Each worker pauses
100 ms between attempts, and has its own progress watchdog.

The proxy applies seeded faults in both directions:

- 2% packet loss, 1% duplication, and 10% delayed packets (up to 50 ms), allowing
  packets to arrive out of order.
- A 30-second blackout every five minutes, long enough to exercise expiry and
  reconnection of established peers.
- Garbage datagrams four times per second per listener.
- Bursts of 32 genuine captured initial ClientHellos from distinct sources every
  two minutes; those sources never return their cookie challenges.

Soak listeners use a pending limit of 16, an admission rate of 16/s, and the
normal five-second negotiation deadline. These smaller limits make saturation
and recovery repeat frequently. Each proxy caps its routing table at 128 entries,
expires idle routes after 15 seconds, and bounds the delayed-packet queue.
The final 30 seconds disable injected faults and verify that every worker makes
progress again.

Defaults are configurable; use `--help` for the complete list. A quick full-matrix
trial can override the timing controls:

```sh
python3 src/sp/transport/dtls/dtls_soak.py \
  --peer mbed=build.mbed/src/sp/transport/dtls/dtls_soak_peer \
  --peer wolf=build.wolf591/src/sp/transport/dtls/dtls_soak_peer \
  --peer openssl=build.openssl13/src/sp/transport/dtls/dtls_soak_peer \
  --duration 90 --warmup 10 --resource-window 10 --sample-interval 5 \
  --fault-period 20 --blackout 2 --storm-period 15 --recovery 20 \
  --watchdog 45 --output .context/dtls-soak-trial
```

## Observation and pass criteria

`progress.md` provides a live, compact report; `status.json` is updated atomically
every 15 seconds with the full data. It includes elapsed time,
phase, per-worker verified replies, bytes, socket cycles and timeouts, server
admission counters, proxy fault counts, and current process resources. The
status JSON also records the proxy runner's resources and their peaks.
`samples.jsonl` preserves the history, and individual peer JSONL/stderr files
retain protocol diagnostics. `manifest.json` records the seed, arguments,
backend descriptions, executable hashes, sanitizer options, and repository
revision (when git is available); `source/` preserves the harness, transport,
and common TLS sources used for the run.

The run fails on early peer exit, missing heartbeat or worker progress for
90 seconds, a mismatched reply, an admission gauge above the configured bound,
proxy exhaustion, missing stress phases, or failed recovery. It also samples
current RSS, file descriptor counts, and thread counts. After a five-minute
warmup, sustained growth over a one-minute window is limited to 32 MiB RSS,
16 descriptors, or four threads above each process's warmup peak. The absolute
RSS ceiling is 512 MiB per peer. Transient allocator peaks do not fail the run.
The raw history remains available to inspect smaller trends within these limits.
When running AddressSanitizer, bound its quarantine so retained freed allocations
do not dominate the RSS checks. The Linux sanitizer validation used
`ASAN_OPTIONS=quarantine_size_mb=16:thread_local_quarantine_size_kb=64` with the
same resource limits; the runner records these settings in its manifest.

Successful completion writes `state: "passed"` and exits zero. `summary.md`
contains the result; failures also save a traceback and the last 256 packet
headers/actions per scenario in `network-tail.json`. On macOS, the runner also
attempts to save a thread sample of a peer named in the failure. Set
`NNG_DTLS_SOAK_DEBUG=1` for detailed TLS/transport logs during a reproduction.
A manually interrupted run is recorded as `stopped`, not passed. Stop only the runner and let it clean up
its peers:

```sh
kill -INT <PID from the output directory's runner.pid>
```

A run on one host covers that host's platform code; repeat the workload on other
platforms and with sanitizer builds as part of release validation. The proxy
models datagram faults, rather than real network MTUs or IP fragmentation.
