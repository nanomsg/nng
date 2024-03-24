# nng_ctx_setopt()

## NAME

nng_ctx_setopt --- set context option (deprecated)

## SYNOPSIS

```c
#include <nng/nng.h>

int nng_ctx_setopt(nng_ctx ctx, const char *opt, const void *val, size_t valsz);

int nng_ctx_setopt_bool(nng_ctx ctx, const char *opt, int bval);

int nng_ctx_setopt_int(nng_ctx ctx, const char *opt, int ival);

int nng_ctx_setopt_ms(nng_ctx ctx, const char *opt, nng_duration dur);

int nng_ctx_setopt_size(nng_ctx ctx, const char *opt, size_t z);

int nng_ctx_setopt_string(nng_ctx ctx, const char *opt, const char *str);

int nng_ctx_setopt_uint64(nng_ctx ctx, const char *opt, uint64_t u64);
```

## DESCRIPTION

> [!IMPORTANT]
> These functions are deprecated.
> Please see [nng_ctx_set()](nng_ctx_set.md).
> They may not be present if the library was built with `NNG_ELIDE_DEPRECATED`.
> They may also be removed entirely in a future version of _NNG_.

The `nng_ctx_setopt()` functions are used to configure options for
the context _ctx_.
The actual options that may be configured in this way vary, and are
specified by _opt_.

> [!NOTE]
> Context options are protocol specific.
> The details will be documented with the protocol.

### Forms

The details of the type, size, and semantics of the option will depend
on the actual option, and will be documented with the option itself.

- `nng_ctx_setopt()`:\
  This function is untyped, and can be used to configure any arbitrary data.
  The _val_ pointer addresses the data to copy, and _valsz_ is the
  size of the objected located at _val_.

- `nng_ctx_setopt_bool()`:\
  This function is for options which take a Boolean (`bool`).
  The _bval_ is passed to the option.

- `nng_ctx_setopt_int()`:\
  This function is for options which take an integer (`int`).
  The _ival_ is passed to the option.

- `nng_ctx_setopt_ms()`:\
  This function is used to configure time durations (such as timeouts) using
  type [`nng_duration`](nng_duration.md).
  The duration _dur_ is an integer number of milliseconds.

- `nng_ctx_setopt_size()`:\
  This function is used to configure a size, _z_, typically for buffer sizes,
  message maximum sizes, and similar options.

- `nng_ctx_setopt_string()`:\
  This function is used to pass configure a string, _str_.
  Strings passed this way must be legal UTF-8 or ASCII strings, terminated
  with a `NUL` (`\0`) byte.
  (Other constraints may apply as well, see the documentation for each option
  for details.)

- `nng_ctx_setopt_uint64()`:\
  This function is used to configure a 64-bit unsigned value, _u64_.
  This is typically used for options related to identifiers, network numbers,
  and similar.

## RETURN VALUES

These functions return 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_ECLOSED`: Parameter _s_ does not refer to an open socket.
- `NNG_EINVAL`: The value being passed is invalid.
- `NNG_ENOTSUP`: The option _opt_ is not supported.
- `NNG_EREADONLY`: The option _opt_ is read-only.
- `NNG_ESTATE`: The socket is in an inappropriate state for setting this option.

## SEE ALSO

[nng_ctx_set()](nng_ctx_set.md),
[nng_ctx](nng_ctx.md),
[nng_options](nng_options.md)