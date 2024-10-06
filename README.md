# nng - nanomsg-next-gen

[![Stand With Ukraine](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/badges/StandWithUkraine.svg)](https://stand-with-ukraine.pp.ua)
[![Linux Status](https://img.shields.io/github/actions/workflow/status/nanomsg/nng/linux.yml?branch=dev2.0&logoColor=grey&logo=ubuntu&label=)](https://github.com/nanomsg/nng/actions)
[![Windows Status](https://img.shields.io/github/actions/workflow/status/nanomsg/nng/windows.yml?branch=dev2.0&logoColor=grey&logo=data:image/svg%2bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0ODc1IDQ4NzUiPjxwYXRoIGZpbGw9ImdyZXkiIGQ9Ik0wIDBoMjMxMXYyMzEwSDB6bTI1NjQgMGgyMzExdjIzMTBIMjU2NHpNMCAyNTY0aDIzMTF2MjMxMUgwem0yNTY0IDBoMjMxMXYyMzExSDI1NjQiLz48L3N2Zz4=&label=)](https://github.com/nanomsg/nng/actions)
[![macOS Status](https://img.shields.io/github/actions/workflow/status/nanomsg/nng/darwin.yml?branch=dev2.0&logoColor=grey&logo=apple&label=)](https://github.com/nanomsg/nng/actions)
[![Coverage](https://img.shields.io/codecov/c/github/nanomsg/nng?logo=codecov&logoColor=grey&label=)](https://codecov.io/gh/nanomsg/nng)
[![Discord](https://img.shields.io/discord/639573728212156478?label=&logo=discord)](https://discord.gg/Xnac6b9)
[![Manual](https://img.shields.io/static/v1?label=&message=docs&logo=asciidoctor&logoColor=silver&color=blue)](https://nng.nanomsg.org/man)
[![MIT License](https://img.shields.io/github/license/nanomsg/nng.svg?logoColor=silver&logo=open-source-initiative&label=&color=blue)](https://github.com/nanomsg/nng/blob/dev2.0/LICENSE.txt)
[![Latest Version](https://img.shields.io/github/v/tag/nanomsg/nng.svg?logo=github&label=)](https://github.com/nanomsg/nng/releases)

Please see [here](UKRAINE) for an important message for the people of Russia.

> [!NOTE] > _THIS IS THE DEVELOPMENT BRANCH FOR NNG._ The content here is
> under development and may not be suitable for production use.
> Please use the [`stable`](https://github.com/nanomsg/nng/tree/stable) branch
> for the latest stable release.

> [!NOTE]
> If you are looking for the legacy version of nanomsg, please
> see the [libnanomsg](https://github.com/nanomsg/nanomsg) repository.

This project is a rewrite of the Scalability Protocols
library known as [nanomsg](https://github.com/nanomsg/nanomsg),
and adds significant new capabilities, while retaining
compatibility with the original.

It may help to think of this as "nanomsg-next-generation".

## NNG: Lightweight Messaging Library

NNG, like its predecessors [nanomsg](http://nanomsg.org) (and to some extent
[ZeroMQ](http://zeromq.org/)), is a lightweight, broker-less library,
offering a simple API to solve common recurring messaging problems,
such as publish/subscribe, RPC-style request/reply, or service discovery.
The API frees the programmer from worrying about details like connection
management, retries, and other common considerations, so that they
can focus on the application instead of the plumbing.

NNG is implemented in C, requiring only C99 and CMake to build.
It can be built as a shared or a static library, and is readily
embeddable. It is also designed to be easy to port to new platforms
if your platform is not already supported.

## License

NNG is licensed under a liberal, and commercial friendly, MIT license.
The goal to the license is to minimize friction in adoption, use, and
contribution.

## Enhancements (Relative to nanomsg)

Here are areas where this project improves on "nanomsg":

- _Reliability_

  NNG is designed for production use from the beginning.
  Every error case is considered, and it is designed to avoid crashing except
  in cases of gross developer error.
  (Hopefully we don't have any of these in our own code.)

- _Scalability_

  NNG scales out to engage multiple cores using a bespoke asynchronous I/O
  framework, using thread pools to spread load without exceeding typical
  system limits.

- _Maintainability_

  NNG's architecture is designed to be modular and easily grasped by developers
  unfamiliar with the code base. The code is also well documented.

- _Extensibility_

  Because it avoids ties to file descriptors, and avoids confusing interlocking
  state machines, it is easier to add new protocols and transports to NNG.
  This was demonstrated by the addition of the TLS and ZeroTier transports.

- _Security_

  NNG provides TLS (1.2 and optionally 1.3) and ZeroTier transports, offering
  support for robust and industry standard authentication and encryption.
  In addition, it is hardened to be resilient against malicious attackers,
  with special consideration given to use in a hostile Internet.

- _Usability_

  NNG eschews slavish adherence parts of the more complex and less well
  understood POSIX APIs, while adopting the semantics that are familiar and
  useful. New APIs are intuitive, and the optional support for separating
  protocol context and state from sockets makes creating concurrent
  applications vastly simpler than previously possible.

## Compatibility

This project offers both wire compatibility and API compatibility,
so most nanomsg users can begin using NNG right away.

Existing nanomsg and https://github.com/nanomsg/mangos[mangos] applications
can inter-operate with NNG applications automatically.

That said, there are some areas where legacy nanomsg still offers
capabilities NNG lacks -- specifically enhanced observability with
statistics, and tunable prioritization of different destinations
are missing, but will be added in a future release.

Additionally, some API capabilities that are useful for foreign
language bindings are not implemented yet.

Some simple single threaded, synchronous applications may perform better under
legacy nanomsg than under NNG. (We believe that these applications are the
least commonly deployed, and least interesting from a performance perspective.
NNG's internal design is slightly less efficient in such scenarios, but it
greatly benefits when concurrency or when multiple sockets or network peers
are involved.)

## Supported Platforms

NNG supports Linux, macOS, Windows (Vista or better), illumos, Solaris,
FreeBSD, Android, and iOS. Most other POSIX platforms should work out of
the box but have not been tested. Very old versions of otherwise supported
platforms might not work.

Officially, NNG only supports operating systems that are supported by
their vendors. For example, Windows versions 8.1 and lower are no longer
officially supported.

## Requirements

To build this project, you will need a C99 compatible compiler and
[CMake](http://www.cmake.org) version 3.15 or newer.

We recommend using the [Ninja](https://ninja-build.org) build
system (pass `-G Ninja` to CMake) when you can.
(And not just because Ninja sounds like "NNG" -- it's also
blindingly fast and has made our lives as developers measurably better.)

If you want to build with TLS support you will also need
[Mbed TLS](https://tls.mbed.org).
See the [build instructions](docs/BUILD_TLS.md) for details.

## Quick Start

With a Linux or UNIX environment:

```sh
$ mkdir build
$ cd build
$ cmake -G Ninja ..
$ ninja
$ ninja test
$ ninja install
```

## API Documentation

The API documentation is provided in Asciidoc format in the
`docs/man` subdirectory, and also
[online](https://nanomsg.github.io/nng).

> [!NOTE]
> However, an effort to convert the documentation to Markdown using `mdbook`
> is underway.

The [_nng_(7)](docs/man/nng.7.adoc) page provides a conceptual overview and links to
manuals for various patterns.
The [_libnng_(3)](docs/man/libnng.3.adoc) page is a good starting point for the API reference.

You can also purchase a copy of the
[**NNG Reference Manual**](http://staysail.tech/books/nng_reference/index.html).
(It is published in both electronic and printed formats.)
Purchases of the book help fund continued development of NNG.

## Example Programs

Some demonstration programs have been created to help serve as examples.
These are located in the `demo` directory.

## Legacy Compatibility

A legacy `libnanomsg` compatible API is available, and while it offers
less capability than the modern NNG API, it may serve as a transition aid.
Please see [_nng_compat_(3)](docs/man/nng_compat.3compat.adoc) for details.

## Commercial Support

Commercial support for NNG is available.

Please contact
[Staysail Systems, Inc.](mailto:info@staysail.tech)
to inquire further.

## Commercial Sponsors

The development of NNG has been made possible through the generous
sponsorship of
[Capitar IT Group BV](https://www.capitar.com)
and
[Staysail Systems, Inc.](http://staysail.tech).
