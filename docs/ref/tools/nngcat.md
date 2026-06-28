# nngcat

`nngcat` is a command-line peer for Scalability Protocols. It is useful for
testing services, building small shell-script integrations, demonstrating
topologies, and inspecting messages without writing a custom program.

Every `nngcat` invocation has the same basic shape:

```sh
nngcat --PROTOCOL --dial URL [send-options] [receive-options]
nngcat --PROTOCOL --listen URL [send-options] [receive-options]
```

At least one protocol option and at least one peer address are required. The
selected protocol determines whether the command sends messages, receives
messages, or performs an exchange involving both.

Use `nngcat --help` for command-line help and `nngcat --version` to print the
version.

## Basic Examples

This starts a reply peer that always answers `42`, then sends one request to it:

```sh
addr="tcp://127.0.0.1:4567"
nngcat --rep --listen="${addr}" --data="42" --quoted &
nngcat --req --dial="${addr}" --data="what is the answer?" --quoted
```

The requester prints both the request and reply:

```text
"what is the answer?"
"42"
```

This publishes a message once per hour over IPC and receives it with a
subscriber:

```sh
addr="ipc:///grandpa_clock"
nngcat --pub --listen="${addr}" --data="cuckoo" --delay 1 --interval 3600 &
nngcat --sub --dial="${addr}" --quoted --count 1
```

The subscriber prints:

```text
"cuckoo"
```

## Choosing a Protocol

Exactly one protocol family should be selected for a command.

| Options | Protocol | Use |
| --- | --- | --- |
| `--bus`, `--bus0` | [BUS][bus] | Send and receive messages among bus peers. |
| `--req`, `--req0` | [REQ][req] | Send requests to [REP][rep] peers and receive replies. |
| `--rep`, `--rep0` | [REP][rep] | Receive requests from [REQ][req] peers and send replies. |
| `--pub`, `--pub0` | [PUB][pub] | Publish messages to [SUB][sub] peers. |
| `--sub`, `--sub0` | [SUB][sub] | Receive messages from [PUB][pub] peers, filtered by subscription. |
| `--push`, `--push0` | [PUSH][push] | Send pipeline messages to [PULL][pull] peers. |
| `--pull`, `--pull0` | [PULL][pull] | Receive pipeline messages from [PUSH][push] peers. |
| `--pair0` | [PAIR][pair] v0 | Exchange messages with one PAIR v0 peer. |
| `--pair1` | [PAIR][pair] v1 | Exchange messages with one PAIR v1 peer. |
| `--pair` | [PAIR][pair] | Alias for `--pair1`, or `--pair0` in `--compat` mode. |
| `--surveyor`, `--surveyor0` | [SURVEYOR][surveyor] | Send a survey and receive respondent replies. |
| `--respondent`, `--respondent0` | [RESPONDENT][respondent] | Receive surveys and send responses. |

`nngcat` does not support PAIR v1 polyamorous mode, although peers may use it.

## Connecting and Listening

Use `--dial` or `--connect` to connect to a peer:

```sh
nngcat --req --dial tcp://127.0.0.1:4567 --data "status"
```

Use `--listen` or `--bind` to accept connections from peers:

```sh
nngcat --rep --listen tcp://127.0.0.1:4567 --data "ok"
```

Unlike the legacy `nanocat` tool, `nngcat` can use more than one peer address in
a single invocation.

Shortcut options are available for common TCP and IPC addresses:

| Option | Equivalent |
| --- | --- |
| `-x PATH`, `--connect-ipc PATH` | `--connect ipc://PATH` |
| `-X PATH`, `--bind-ipc PATH` | `--bind ipc://PATH` |
| `-l PORT`, `--connect-local PORT` | `--connect tcp://127.0.0.1:PORT` |
| `-L PORT`, `--bind-local PORT` | `--bind tcp://127.0.0.1:PORT` |

## Sending Data

Protocols that send messages use `--data` or `--file` to choose the outgoing
message body:

```sh
nngcat --push --dial tcp://127.0.0.1:9000 --data "hello"
nngcat --push --dial tcp://127.0.0.1:9000 --file payload.bin
```

If `--file -` is used, the message body is read from standard input.

For protocols that send unsolicited messages, such as PUB or PUSH, `--interval`
repeats the outgoing message and `--delay` waits before sending the first
message. A delay is often useful with PUB sockets because subscribers may need
time to connect before the first message is sent.

```sh
nngcat --pub --listen tcp://127.0.0.1:9000 --data tick --delay 1 --interval 5
```

Use `--send-timeout` to give up if a send cannot complete within the requested
number of seconds.

## Receiving Data

Protocols that receive messages can format output in several ways:

| Format | Output |
| --- | --- |
| `no` | Suppress output. |
| `raw` | Write received bytes directly to standard output. |
| `ascii` | Print safe ASCII directly and replace other bytes with `.`. |
| `quoted` | Print messages as C-style quoted strings. |
| `hex` | Print each byte as an escaped hexadecimal value such as `\x2e`. |
| `msgpack` | Emit MessagePack bin-format byte arrays. |

The format can be selected with `--format FORMAT` or one of the convenience
aliases:

| Option | Equivalent |
| --- | --- |
| `-A`, `--ascii` | `--format ascii` |
| `-Q`, `--quoted` | `--format quoted` |
| `--hex` | `--format hex` |
| `--msgpack` | `--format msgpack` |
| `--raw` | `--format raw` |

For SUB sockets, use `--subscribe TOPIC` to receive only messages whose initial
bytes match `TOPIC`. This option may be used more than once. If no subscription
is supplied, `nngcat` subscribes to all messages.

Use `--receive-timeout` to stop waiting after the requested number of seconds,
and `--recv-maxsz` to set the largest message size accepted by the socket. The
default receive limit is 1 MiB. Use `--recv-maxsz 0` to remove the limit.

## TLS

TLS options are used only with TLS-secured addresses, such as `tls+tcp://`
URLs. They are ignored for non-TLS transports.

Use `--cacert FILE` to supply certificate authorities for peer validation. Use
`--cert FILE` and `--key FILE` to present a local certificate and private key.
If `--cert` is supplied without `--key`, the certificate file is expected to
contain both the certificate and private key.

`--insecure` disables peer validation. This is useful for local testing with
self-signed certificates, but it should not be used for production traffic.

## Option Syntax

Long options start with `--`. If a long option takes a value, the value can be
supplied with an equals sign, with a colon, or as the next argument:

```sh
nngcat --subscribe=times
nngcat --subscribe:tribune
nngcat --subscribe herald
```

Short options start with `-`. If a short option takes a value, the value can be
attached to the option or supplied as the next argument:

```sh
nngcat -L5678
nngcat -L 5678
```

Long options may be abbreviated as long as the abbreviation is unambiguous. For
example, `--comp` can be used instead of `--compat`, but `--re` is ambiguous
because it could mean `--req`, `--rep`, or `--respondent`.

POSIX-style clustering of short options is not supported. Each short option must
be supplied as a separate argument.

## Option Reference

### Generic Options

| Option | Description |
| --- | --- |
| `-h`, `--help` | Print usage help. |
| `-V`, `--version` | Print the version and exit. |
| `-v`, `--verbose` | Use verbose operation. |
| `-q`, `--silent` | Use silent operation. |
| `--compat` | Behave more like legacy `nanocat`: connections are asynchronous, and `--pair` selects PAIR v0 instead of PAIR v1. |
| `--subscribe TOPIC` | Subscribe a SUB socket to `TOPIC`. May be specified multiple times. |
| `--count COUNT` | Limit loop iterations. Send-only protocols send `COUNT` messages, receive-only protocols receive `COUNT` messages, and exchange protocols perform `COUNT` exchanges. A value of `0` means unlimited iterations. |

### Protocol Selection Options

| Option | Description |
| --- | --- |
| `--bus`, `--bus0` | Select BUS v0. |
| `--req`, `--req0` | Select REQ v0. |
| `--rep`, `--rep0` | Select REP v0. |
| `--pub`, `--pub0` | Select PUB v0. |
| `--sub`, `--sub0` | Select SUB v0. |
| `--push`, `--push0` | Select PUSH v0. |
| `--pull`, `--pull0` | Select PULL v0. |
| `--pair0` | Select PAIR v0. |
| `--pair1` | Select PAIR v1. |
| `--pair` | Select PAIR v1, or PAIR v0 in `--compat` mode. |
| `--surveyor`, `--surveyor0` | Select SURVEYOR v0. |
| `--respondent`, `--respondent0` | Select RESPONDENT v0. |

### Peer Selection Options

| Option | Description |
| --- | --- |
| `--connect URL`, `--dial URL` | Connect to the peer at `URL`. |
| `--bind URL`, `--listen URL` | Listen for peers at `URL`. |
| `-x PATH`, `--connect-ipc PATH` | Connect to IPC path `PATH`. |
| `-X PATH`, `--bind-ipc PATH` | Listen on IPC path `PATH`. |
| `-l PORT`, `--connect-local PORT` | Connect to `127.0.0.1` TCP port `PORT`. |
| `-L PORT`, `--bind-local PORT` | Listen on `127.0.0.1` TCP port `PORT`. |

### Receive Options

| Option | Description |
| --- | --- |
| `-A`, `--ascii` | Use ASCII-safe output. |
| `-Q`, `--quoted` | Use C-style quoted output. |
| `--hex` | Use escaped hexadecimal output. |
| `--msgpack` | Emit MessagePack bin-format byte arrays. |
| `--raw` | Write raw received bytes. |
| `--format FORMAT` | Select `no`, `raw`, `ascii`, `quoted`, `hex`, or `msgpack` output. |
| `--receive-timeout SEC` | Stop receiving after `SEC` seconds without a message. |
| `--recv-maxsz COUNT` | Set maximum received message size in bytes. The default is 1048576; `0` removes the limit. |

### Transmit Options

| Option | Description |
| --- | --- |
| `-D DATA`, `--data DATA` | Use `DATA` as the outgoing message body. |
| `-F FILE`, `--file FILE` | Use `FILE` as the outgoing message body. Use `-` for standard input. |
| `-i SEC`, `--interval SEC` | Repeat unsolicited sends every `SEC` seconds. |
| `-d SEC`, `--delay SEC` | Wait `SEC` seconds before the first outgoing message. |
| `--send-timeout SEC` | Give up sending after `SEC` seconds. |

### TLS Options

| Option | Description |
| --- | --- |
| `-k`, `--insecure` | Skip peer certificate validation. |
| `-E FILE`, `--cert FILE` | Load this peer's certificate from `FILE`. |
| `--key FILE` | Load this peer's private key from `FILE`. |
| `--cacert FILE` | Load CA certificates from `FILE` for peer validation. |

{{#include ../xref.md}}
