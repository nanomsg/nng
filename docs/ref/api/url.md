# URLs

{{i:Universal Resource Locator}}s, or {{i:URL}}s for short, are a standardized
way of representing a network resource,
defined in [RFC 1738](https://datatracker.ietf.org/doc/html/rfc1738),
and [RFC 3968](https://datatracker.ietf.org/doc/html/rfc3986).

In Scalability Protocols, this concept is extended, although it includes schemes
that are not part of the IETF standards.

## URL Structure

```c
typedef struct nng_url {
    const char *u_scheme;
    char       *u_userinfo;
    char       *u_hostname;
    uint16_t   u_port;
    char       *u_path;
    char       *u_query;
    char       *u_fragment;
} nng_url;

const char *nng_url_scheme(const nng_url *url);
const char *nng_url_userinfo(const nng_url *url);
const char *nng_url_hostname(const nng_url *url);
uint16_t    nng_url_port(const nng_url *url);
const char *nng_url_path(const nng_url *url);
const char *nng_url_query(const nng_url *url);
const char *nng_url_fragment(const nng_url *url):
```

### URL Fields

The {{i:`nng_url_scheme`}} function returns the scheme,
without any colons or slashes. Values are lower case
strings, like "http" or "inproc" or "tls+tcp4".

The {{i:`nng_url_userinfo`}} function returns a string corresponding
to the user component of a URL (the part before any `@` sign) if such
a component is present, otherwise it returns `NULL`.

The {{i:`nng_url_hostname`}} function returns a hostname (which might
actually be an IP address) from the URL, if the URL corresponds to a scheme
that uses hostnames (like "http" or "tcp"). If the URL does not (for example
"inproc" or "ipc" URLs) then it returns `NULL`.

The {{i:`nng_url_port`}} function returns the TCP or UDP port number if the URL
corresponds to a protocol based on TCP or UDP. It returns zero otherwise.
Note that the port number might not have been explicitly specified in the URL.
For example, the port number associated with "http://www.example.com" is 80,
which is the standard port number for HTTP.

> [!TIP]
> The port number returned by this is in the native machine byte order.
> Be careful when using this with other network-oriented APIs.

The {{i:`nng_url_path`}} function returns the path component of the URL.
This will always be non-`NULL`, but it may be empty.

The {{i:`nng_url_query`}} and {{i:`nng_url_fragment`}} functions return
the query-information (the part following a '?') and fragment
(the part following a '#') if those components are present, or `NULL`
if they are not. The returned string will not include the leading '?' or '#'
characters.

Note that any strings returned by these functions are only valid until
_url_ is freed with [`nng_url_free`].

## Format a URL

```c
int nng_url_sprintf(char *buf, size_t bufsz, const nng_url *url);
```

The {{i:`nng_url_sprintf`}} function formats the _url_ to the _buf_,
which must have `bufsz` bytes of free space associated with it.

This function returns the number of bytes formatted to _buf_, excludng
the terminating zero byte, or if _bufsz_ is too small, then it returns
the number of bytes that would have been formatted if there was sufficient
space. The semantics are similar to the `snprintf` function from C99.

> [!TIP]
> If _bufsz_ is 0, then _buf_ can be `NULL`, and the return value
> can be used to determine the amount of space to allocate for a dynamically
> sized buffer.

## Parse a URL

```c
int nng_url_parse(nng_url **urlp, const char *str);
```

The {{i:`nng_url_parse`}} function parses a URL string (in _str_),
and creates a dynamically allocated `nng_url`, returning it in _urlp_.

> [!IMPORTANT]
> Only [`nng_url_free`] should be used to deallocate `nng_url` objects.

## Clone a URL

```c
int nng_url_clone(nng_url **dup, nng_url *url);
```

The {{i:`nng_url_clone`}} function creates a copy of _url_, and returns it in _dup_.

## Destroy a URL

```c
void nng_url_free(nng_url *url);
```

The {{i:`nng_url_free`}} function destroy an `nng_url` object created with
either [`nng_url_parse`] or [`nng_url_free`].

This is the only correct way to destroy an [`nng_url`] object.

## See Also

More information about Universal Resource Locators can be found in
[RFC 3986](https://tools.ietf.org/html/rfc3986).

{{#include ../xref.md}}
