<!-- Concepts -->

[aio]: ../aio/index.md
[context]: ../ctx/index.md
[device]: ../overview/device.md
[duration]: ../overview/duration.md
[msg]: ../msg/index.md
[pipe]: ../overview/pipe.md
[socket]: ../sock/index.md
[sockadddr]: ../overview/sockaddr.md
[sockaddr_in]: ../overview/sockaddr_in.md
[sockaddr_in6]: ../overview/sockaddr_in6.md
[raw]: ../overview/raw.md
[url]: ../overview/url.md
[transport]: ../tran/index.md

<!-- Protocols -->

[bus]: ../proto/bus.md
[pair]: ../proto/pair.md
[pub]: ../proto/pub.md
[pull]: ../proto/pull.md
[push]: ../proto/push.md
[req]: ../proto/req.md
[rep]: ../proto/rep.md
[respondent]: ../proto/respondent.md
[sub]: ../proto/sub.md
[surveyor]: ../proto/surveyor.md

<!-- Transports -->

[inproc]: ../tran/inproc.md
[ipc]: ../tran/ipc.md
[tls]: ../tran/tls.md
[tcp]: ../tran/tcp.md

<!-- Sockets -->

[nng_bus_open]: ../sock/nng_bus_open.md
[nng_pair_open]: ../sock/nng_pair_open.md
[nng_pub_open]: ../sock/nng_pub_open.md
[nng_pull_open]: ../sock/nng_pull_open.md
[nng_push_open]: ../sock/nng_push_open.md
[nng_rep_open]: ../sock/nng_rep_open.md
[nng_req_open]: ../sock/nng_req_open.md
[nng_respondent_open]: ../sock/nng_respondent_open.md
[nng_socket_set]: ../sock/nng_socket_set.md
[nng_sub_open]: ../sock/nng_sub_open.md
[nng_surveyor_open]: ../sock/nng_surveyor_open.md
[nng_close]: ../sock/nng_close.md
[nng_device]: ../sock/nng_device.md

<!-- Messages -->

[nng_msg_alloc]: ../nng_msg_alloc.md
[nng_msg_append]: ../msg/nng_msg_append.md
[nng_msg_body]: ../msg/nng_msg_body.md
[nng_msg_capacity]: ../msg/nng_msg_capacity.md
[nng_msg_chop]: ../msg/nng_msg_chop.md
[nng_msg_clear]: ../msg/nng_msg_clear.md
[nng_msg_dup]: ../msg/nng_msg_dup.md
[nng_msg_free]: ../msg/nng_msg_free.md
[nng_msg_get_pipe]: ../msg/nng_msg_get_pipe.md
[nng_msg_header]: ../msg/nng_msg_header.md
[nng_msg_header_append]: ../msg/nng_msg_header_append.md
[nng_msg_header_chop]: ../msg/nng_msg_header_chop.md
[nng_msg_header_clear]: ../msg/nng_msg_header_clear.md
[nng_msg_header_insert]: ../msg/nng_msg_header_insert.md
[nng_msg_header_len]: ../msg/nng_msg_header_len.md
[nng_msg_header_trim]: ../msg/nng_msg_header_trim.md
[nng_msg_insert]: ../msg/nng_msg_insert.md
[nng_msg_len]: ../msg/nng_msg_len.md
[nng_msg_realloc]: ../msg/nng_msg_realloc.md
[nng_msg_reserve]: ../msg/nng_msg_reserve.md
[nng_msg_set_pipe]: ../msg/nng_msg_set_pipe.md
[nng_msg_trim]: ../msg/nng_msg_trim.md

<!-- Contexts -->

[nng_ctx_close]: ../ctx/nng_ctx_close.md
[nng_ctx_get]: ../ctx/nng_ctx_get.md
[nng_ctx_getopt]: ../ctx/nng_ctx_getopt.md
[nng_ctx_id]: ../ctx/nng_ctx_id.md
[nng_ctx_open]: ../ctx/nng_ctx_open.md
[nng_ctx_recv]: ../ctx/nng_ctx_recv.md
[nng_ctx_recvmsg]: ../nng_ctx_recvmsg.md
[nng_ctx_send]: ../nng_ctx_send.md
[nng_ctx_sendmsg]: ../ctx/nng_ctx_sendmsg.dm
[nng_ctx_set]: ../ctx/nng_ctx_set.md
[nng_ctx_setopt]: ../ctx/nng_ctx_setopt.md

<!-- Async IO -->

[nng_aio_abort]: ../aio/nng_aio_abort.md
[nng_aio_alloc]: ../aio/nng_aio_alloc.md
[nng_aio_busy]: ../aio/nng_aio_busy.md
[nng_aio_cancel]: ../aio/nng_aio_cancel.md
[nng_aio_count]: ../aio/nng_aio_count.md
[nng_aio_free]: ../aio/nng_aio_free.md
[nng_aio_get_msg]: ../aio/nng_aio_get_msg.md
[nng_aio_get_output]: ../aio/nng_aio_get_output.md
[nng_aio_result]: ../aio/nng_aio_result.md
[nng_aio_set_input]: ../aio/nng_aio_set_input.md
[nng_aio_set_iov]: ../aio/nng_aio_set_iov.md
[nng_aio_set_msg]: ../aio/nng_aio_set_msg.md
[nng_aio_set_timeout]: ../aio/nng_aio_set_timeout.md
[nng_aio_stop]: ../aio/nng_aio_stop.md
[nng_aio_wait]: ../aio/nng_aio_wait.md

<!-- IO Provider -->

[nng_aio_begin]: ../iop/nng_aio_begin.md
[nng_aio_defer]: ../iop/nng_aio_defer.md
[nng_aio_finish]: ../iop/nng_aio_finish.md
[nng_aio_get_input]: ../iop/nng_aio_get_input.md
[nng_aio_set_output]: ../iop/nng_aio_set_output.md

<!-- Threads -->

[nng_cv_alloc]: ../thr/nng_cv_alloc.md
[nng_cv_free]: ../thr/nng_cv_free.md
[nng_cv_until]: ../thr/nng_cv_until.md
[nng_cv_wait]: ../thr/nng_cv_wait.md
[nng_cv_wake]: ../thr/nng_cv_wake.md
[nng_cv_wake1]: ../thr/nng_cv_wake1.md
[nng_mtx_alloc]: ../thr/nng_mtx_alloc.md
[nng_mtx_free]: ../thr/nng_mtx_free.md
[nng_mtx_lock]: ../thr/nng_mtx_lock.md
[nng_mtx_unlock]: ../thr/nng_mtx_unlock.md

<!-- Utility -->

[nng_alloc]: ../util/nng_alloc.md
[nng_clock]: ../util/nng_clock.md
[nng_free]: ../util/nng_free.md
[nng_msleep]: ../util/nng_msleep.md
[nng_random]: ../util/nng_random.md
[nng_sleep_aio]: ../util/nng_sleep_aio.md
[nng_strdup]: ../util/nng_strdup.md
[nng_strerror]: ../util/nng_strerror.md
[nng_strfree]: ../util/nng_strfree.md
[nng_version]: ../util/nng_version.md

<!-- Options -->

[NNG_OPT_MAXTTL]: ../opts/nng_opt_max_ttl.md
[NNG_OPT_SENDBUF]: ../opts/nng_opt_sendbuf.md
[NNG_OPT_LOCADDR]: ../opts/nng_opt_locaddr.md
[NNG_OPT_REMADDR]: ../api/nng_options.md#NNG_OPT_REMADDR
[NNG_OPT_TCP_KEEPALIVE]: ../api/nng_tcp_options.md#NNG_OPT_TCP_KEEPALIVE
[NNG_OPT_TCP_NODELAY]: ../api/nng_tcp_options.md#NNG_OPT_TCP_NODELAY
[NNG_OPT_URL]: ../api/nng_options.md#NNG_OPT_URL

<!-- External -->

[mangos]: http://github.com/nanomsg/mangos
[nanomsg]: http://github.com/nanomsg/nanomsg
[survey_rfc]: https://github.com/nanomsg/nanomsg/blob/master/rfc/sp-surveyor-01.txt
