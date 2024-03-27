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

  - [Messages](api/msg/index.md)

    - [nng_msg_alloc](api/msg/nng_msg_alloc.md)
    - [nng_msg_append](api/msg/nng_msg_append.md)
    - [nng_msg_body](api/msg/nng_msg_body.md)
    - [nng_msg_capacity](api/msg/nng_msg_capacity.md)
    - [nng_msg_chop](api/msg/nng_msg_chop.md)
    - [nng_msg_clear](api/msg/nng_msg_clear.md)
    - [nng_msg_dup](api/msg/nng_msg_dup.md)
    - [nng_msg_free](api/msg/nng_msg_free.md)
    - [nng_msg_get_pipe](api/msg/nng_msg_get_pipe.md)
    - [nng_msg_header](api/msg/nng_msg_header.md)
    - [nng_msg_header_append](api/msg/nng_msg_header_append.md)
    - [nng_msg_header_chop](api/msg/nng_msg_header_chop.md)
    - [nng_msg_header_clear](api/msg/nng_msg_header_clear.md)
    - [nng_msg_header_insert](api/msg/nng_msg_header_insert.md)
    - [nng_msg_header_len](api/msg/nng_msg_header_len.md)
    - [nng_msg_header_trim](api/msg/nng_msg_header_trim.md)
    - [nng_msg_insert](api/msg/nng_msg_insert.md)
    - [nng_msg_len](api/msg/nng_msg_len.md)
    - [nng_msg_realloc](api/msg/nng_msg_realloc.md)
    - [nng_msg_reserve](api/msg/nng_msg_reserve.md)
    - [nng_msg_set_pipe](api/msg/nng_msg_set_pipe.md)
    - [nng_msg_trim](api/msg/nng_msg_trim.md)

  - [Sockets](api/socket/index.md)

    - [nng_bus_open](api/socket/nng_bus_open.md)
    - [nng_close](api/socket/nng_close.md)
    - [nng_pub_open](api/socket/nng_pub_open.md)

  - [Contexts](api/context/index.md)

    - [nng_ctx_close](api/context/nng_ctx_close.md)
    - [nng_ctx_get](api/context/nng_ctx_get.md)
    - [nng_ctx_getopt](api/context/nng_ctx_getopt.md)
    - [nng_ctx_id](api/context/nng_ctx_id.md)
    - [nng_ctx_open](api/context/nng_ctx_open.md)
    - [nng_ctx_recv](api/context/nng_ctx_recv.md)
    - [nng_ctx_recvmsg](api/context/nng_ctx_recvmsg.md)
    - [nng_ctx_send](api/context/nng_ctx_send.md)
    - [nng_ctx_sendmsg](api/context/nng_ctx_sendmsg.md)
    - [nng_ctx_set](api/context/nng_ctx_set.md)
    - [nng_ctx_setopt](api/context/nng_ctx_setopt.md)

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
    - [nng_random](api/util/nng_random.md)
    - [nng_strerror](api/util/nng_strerror.md)
    - [nng_version](api/util/nng_version.md)

  - [Threads and Synchronization](api/threads/index.md)

    - [nng_cv_alloc](api/threads/nng_cv_alloc.md)
    - [nng_cv_free](api/threads/nng_cv_free.md)
    - [nng_cv_until](api/threads/nng_cv_until.md)
    - [nng_cv_wait](api/threads/nng_cv_wait.md)
    - [nng_cv_wake](api/threads/nng_cv_wake.md)
    - [nng_cv_wake1](api/threads/nng_cv_wake1.md)

  - [Legacy Compatibility](api/compat/index.md)

- [Index](./indexing.md)
