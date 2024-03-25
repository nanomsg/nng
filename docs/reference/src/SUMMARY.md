# Summary

- [Chapter 1](./chapter_1.md)

- [Overview](./overview/index.md)

  - [RAW mode](./overview/raw.md)

- [Protocols](./protocols/index.md)

  - [BUS](protocols/bus.md)
  - [PUB](protocols/pub.md)
  - [REP](protocols/rep.md)

- [Transports](./transports/index.md)

  - [INPROC](transports/inproc.md)
  - [TCP](transports/tcp.md)

- [API Reference](./api/index.md)

  - [Asynchronous I/O](./api/aio/index.md)

    - [nng_aio_abort](api/aio/nng_aio_abort.md)
    - [nng_aio_alloc](api/aio/nng_aio_alloc.md)
    - [nng_aio_busy](api/aio/nng_aio_busy.md)
    - [nng_aio_cancel](api/aio/nng_aio_cancel.md)
    - [nng_aio_count](api/aio/nng_aio_count.md)
    - [nng_aio_free](api/aio/nng_aio_free.md)
    - [nng_aio_get_msg](api/aio/nng_aio_get_msg.md)
    - [nng_aio_get_output](api/aio/nng_aio_get_output.md)
    - [nng_aio_result](api/aio/nng_aio_result.md)
    - [nng_aio_set_input](api/aio/nng_aio_set_input.md)
    - [nng_aio_set_iov](api/aio/nng_aio_set_iov.md)
    - [nng_aio_set_msg](api/aio/nng_aio_set_msg.md)
    - [nng_aio_set_timeout](api/aio/nng_aio_set_timeout.md)
    - [nng_aio_stop](api/aio/nng_aio_stop.md)
    - [nng_aio_wait](api/aio/nng_aio_wait.md)

  - [Asynchronous I/O for Providers](api/aio_provider/index.md)

    - [nng_aio_begin](api/aio_provider/nng_aio_begin.md)
    - [nng_aio_defer](api/aio_provider/nng_aio_defer.md)
    - [nng_aio_finish](api/aio_provider/nng_aio_finish.md)
    - [nng_aio_get_input](api/aio_provider/nng_aio_get_input.md)
    - [nng_aio_set_output](api/aio_provider/nng_aio_set_output.md)

  - [Utility Functions](api/util/index.md)

    - [nng_alloc](api/util/nng_alloc.md)
    - [nng_clock](api/util/nng_clock.md)
    - [nng_free](api/util/nng_free.md)
    - [nng_version](api/util/nng_version.md)
    - [nng_cv_alloc](api/nng_cv_alloc.md)
    - [nng_cv_free](api/nng_cv_free.md)
    - [nng_cv_until](api/nng_cv_until.md)
    - [nng_cv_wait](api/nng_cv_wait.md)
    - [nng_cv_wake](api/nng_cv_wake.md)
    - [nng_cv_wake1](api/nng_cv_wake1.md)

  - [Context Functions](api/context.md)

    - [nng_ctx](api/nng_ctx.md)
    - [nng_ctx_close](api/nng_ctx_close.md)
    - [nng_ctx_get](api/nng_ctx_get.md)
    - [nng_ctx_getopt](api/nng_ctx_getopt.md)
    - [nng_ctx_id](api/nng_ctx_id.md)
    - [nng_ctx_open](api/nng_ctx_open.md)
    - [nng_ctx_recv](api/nng_ctx_recv.md)
    - [nng_ctx_recvmsg](api/nng_ctx_recvmsg.md)
    - [nng_ctx_send](api/nng_ctx_send.md)
    - [nng_ctx_sendmsg](api/nng_ctx_sendmsg.md)
    - [nng_ctx_set](api/nng_ctx_set.md)
    - [nng_ctx_setopt](api/nng_ctx_setopt.md)

  - [Protocol Sockets](api/protocol.md)

    - [nng_bus_open](api/nng_bus_open.md)
    - [nng_close](api/nng_close.md)

  - [Legacy Compatibility](api/compat/index.md)

- [Index](./indexing.md)
