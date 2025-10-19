# Building for TLS Support

If you want to include support for Transport Layer Security
(`tls+tcp://` and `wss://` URLs) you should follow these directions.

TLS support in NNG depends on a suitable TLS library.
The options are [Mbed TLS](https://tls.mbed.org/),
[WolfSSL](https://www.wolfssl.com/), [OpenSSL](https://openssl.org).

> [!IMPORTANT]
> These libraries are licensed under different terms than NNG.
> You are responsible for reading those license terms, and ensuring
> that your use conforms to them.

> [!TIP]
> This project receives no compensation or support in any other form
> from either ARM (owners of the Mbed TLS project) or WolfSSL.
> Thus, as a special request, if you're paying for commercial licenses for
> either Mbed TLS or WolfSSL for use with NNG, please consider also sponsoring
> this project or obtaining a commercial support contract from
> [Staysail Systems, Inc.](https://www.staysail.tech/)
> You can enquire about support contracts at info@staysail.tech.
> Sponsorship information is available on our
> [GitHub page](https://github.com/nanomsg/nng). Thank you!

On many distributions you may be able to install a pre-packaged version
of either library. We recommend doing so if this is an option for you.
For example, Ubuntu users can install the `libmbedtls-dev` package.

You can also build these from source; if you choose to do so,
please make sure you also _install_ it somewhere (even a temporary
staging directory).

## Notes about Mbed TLS

MbedTLS 2.28 or 3.6 are tested and known to work.
MbedTLS 4.0 is not at present supported, but we will work to
address that soon. Support for MbedTLS 2.28 may be dropped
before NNG 2.0 finalizes, as it is no longer supported by
the Mbed TLS project.

## Notes about WolfSSL

WolfSSL can be configured with a small subset of possible
features, which can impair NNG's functionality. We recommend
enabling support for peer certificates as well as the optional
extra OpenSSL compatibility APIs.

Note that the open source version of WolfSSL is GPLv3, which
applies significant additional considerations on users. Please
check with your lawyer if you're not planning to open source
your work under GPLv3 as well.

We have not tested NNG with the commercial version of WolfSSL.
If you want support for that, please contact Staysail Systems
to make support arrangements.

## Notes about OpenSSL

OpenSSL requires version 3.5 or newer. (As of this writing, OpenSSL
3.5 is the most recent long term support - LTS - release of OpenSSL.)
No effort will be made to support earlier releases.

## Configuring NNG with TLS

TLS support is not enabled by default, but can be enabled by configuring
with the CMake option `NNG_ENABLE_TLS=ON`.

You can select which library to use by using `NNG_TLS_ENGINE=mbed`,
`NNG_TLS_ENGINE=wolf`, or `NNG_TLS_ENGINE=openssl`.
If you do not specify an engine, then `mbed` is assumed by default.
(Note that the default may change in future releases.)

By default NNG searches for an installed components in `/usr/local`,
as well as the normal installation directories for libraries on your system.

If you have installed the TLS library elsewhere, you can direct the NNG configuration
to it by setting the `MBEDTLS_ROOT_DIR` or `WOLFSSL_ROOT_DIR` CMake variable
as appropriate. For OpenSSL, see the CMake documentation for `FindOpenSSL`.

## Example

The following example would work on either Linux or macOS, and assumes
that we have checked out github source trees into `$HOME/work`.
It also assumes that Mbed TLS is already installed in `/usr/local` or
a standard search path.

```

$ export NNGDIR=$HOME/work/nng
$ mkdir build
$ cd build

$ cmake -G Ninja -DNNG_ENABLE_TLS=ON ..

... (lots of lines of output from cmake...)

$ ninja build

... (lots of lines of output from ninja...)

$ ./src/supplemental/tls/tls_test -v

... (lots of lines of output from the test ...)

Summary:
  Count of all unit tests:        9
  Count of run unit tests:        9
  Count of failed unit tests:     0
  Count of skipped unit tests:    0
SUCCESS: All unit tests have passed.
```
