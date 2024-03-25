# Asynchronous I/O for Providers

I/O providers perform the operations that are linked to
an [`nng_aio`](../aio/index.md) object, on behalf of applications
that submit requests for the same operations.

Most applications will not use the functions listed here.
Applications that implement their own HTTP handler functions, or
custom transport providers, might make use of these functions.

In addition to these functions, I/O providers may utilize the
other consumer functions for [Aysnchronous I/O](../aio/index.md).

## See Also

[nng_aio_begin()](nng_aio_begin.md),
[nng_aio_defer()](nng_aio_defer.md),
[nng_aio_finish()](nng_aio_finish.md),
[nng_aio_get_input()](nng_aio_get_input.md),
[nng_aio_set_output()](nng_aio_set_output.md),
[Asynchronous I/O](../aio/index.md)
