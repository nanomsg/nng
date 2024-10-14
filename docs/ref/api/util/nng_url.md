# nng_url

## NAME

nng_url --- Universal Resource Locator object

## SYNOPSIS

```c
#include <nng/nng.h>

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

int nng_url_parse(nng_url **urlp, const char *str);
int nng_url_clone(nng_url **dup, nng_url *url);
void nng_url_free(nng_url *url);
```

## DESCRIPTION

An {{i:`nng_url`}}{{hi:URL}}{{hi:Universal Resource Locator}} is a structure used for representing URLs.
These structures are created by parsing string formatted URLs with {{i:`nng_url_parse`}}.

An `nng_url` may be cloned using the {{i:`nng_url_clone`}} function.
The original _url_ is duplicated into the location specified by _dup_.

When no longer needed, `nng_url` objects may be freed using {{i:`nng_url_free`}}.

> [!IMPORTANT]
> Only `nng_url_free` should be used to deallocate `nng_url` objects.

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

> [!TIP]
> More information about Universal Resource Locators can be found in
> [RFC 3986](https://tools.ietf.org/html/rfc3986).

## RETURN VALUES

The `nng_url_parse` and `nng_url_clone` functions return zero on success, or a non-zero
error value.

## ERRORS

- `NNG_ENOMEM`: Insufficient free memory exists.
- `NNG_EINVAL`: The supplied string does not represent a valid URL.
