# nng_version

## NAME

nng_version --- report library version

## SYNOPSIS

```c
#include <nng/nng.h>

const char * nng_version(void);
```

## DESCRIPTION

The {{i:`nng_version`}} function returns a human readable {{i:version number}}
for _NNG_.

Additionally, compile time version information is available
via some predefined macros:

- {{i:`NNG_MAJOR_VERSION`}}: Major version number.
- {{i:`NNG_MINOR_VERSION`}}: Minor version number.
- {{i:`NNG_PATCH_VERSION`}}: Patch version number.

_NNG_ is developed and released using
[Semantic Versioning 2.0](http://www.semver.org), and
the version numbers reported refer to both the API and the library itself.
(The {{i:ABI}} -- {{i:application binary interface}} -- between the
library and the application is controlled in a similar, but different
manner depending upon the link options and how the library is built.)

## RETURN VALUES

`NUL`-terminated string containing the library version number.
