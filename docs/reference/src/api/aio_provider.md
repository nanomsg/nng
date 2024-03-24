# Asynchronous I/O for Providers

This section documents functions used when implementing I/O providers.

I/O providers actually perform the operations that are linked to
an [`nng_aio`](nng_aio.md) object.

Most applications will not use the functions listed here.
Applications the implement their own HTTP handler functions, or
custom transport providers, might make use of these functions.
