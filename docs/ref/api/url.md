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
    char *u_rawurl;
    char *u_scheme;
    char *u_userinfo;
    char *u_host;
    char *u_hostname;
    char *u_port;
    char *u_path;
    char *u_query;
    char *u_fragment;
    char *u_requri;
} nng_url;
```

### URL Fields

Applications may access individual fields, but must not free or
alter them, as the underlying memory is managed by the library.

The fields of an `nng_url` object are as follows:

- `u_rawurl`: The unparsed URL string. This will never be `NULL`.
- `u_scheme`: The URL scheme, such as "http" or "inproc". Always lower case. This will never be `NULL`.
- `u_userinfo`: This username and password if supplied in the URL string. Will be `NULL` when not present.
- `u_host`: The full host part of the URL, including the port if present (separated by a colon.)
- `u_hostname`: The name of the host, and may be the empty string in some cases.
- `u_port`: The port. May be empty if irrelevant or not specified.
- `u_path`: The path, typically used with HTTP or WebSockets. Will be empty string if not specified.
- `u_query`: The query info (typically following `?` in the URL.) Will be `NULL` if not present.
- `u_fragment`: This is used for specifying an anchor, the part after `#` in a URL. Will be `NULL` if not present.
- `u_requri`: The full Request-URI. Will be the empty string if not specified.

> [!NOTE]
> Other fields may also be present, but only those documented here are safe for application use.

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
