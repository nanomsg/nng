<!-- Symbol cross reference -->

[`nng_alloc`]: /api/memory.md#allocate-memory
[`nng_free`]: /api/memory.md#deallocate-memory
[`nng_strdup`]: /api/memory.md#duplicate-string
[`nng_strfree`]: /api/memory.md#free-string
[`nng_time`]: /api/time.md#time-type
[`nng_duration`]: /api/time.md#duration-type
[`nng_clock`]: /api/time.md#getting-the-current-time
[`nng_msleep`]: /api/time.md#waiting-for-duration
[`nng_msg`]: /api/msg.md#message-structure
[`nng_msg_alloc`]: /api/msg.md#create-a-message
[`nng_msg_free`]: /api/msg.md#destroy-a-message
[`nng_msg_body`]: /api/msg.md#message-body
[`nng_msg_len`]: /api/msg.md#message-body
[`nng_msg_clear`]: /api/msg.md#clear-the-body
[`nng_msg_capacity`]: /api/msg.md#message-size-and-capacity
[`nng_msg_realloc`]: /api/msg.md#message-size-and-capacity
[`nng_msg_reserve`]: /api/msg.md#message-size-and-capacity
[`nng_msg_append`]: /api/msg.md#add-to-body
[`nng_msg_insert`]: /api/msg.md#add-to-body
[`nng_msg_chop`]: /api/msg.md#consume-from-body
[`nng_msg_trim`]: /api/msg.md#consume-from-body
[`nng_msg_header`]: /api/msg.md#message-header
[`nng_msg_header_len`]: /api/msg.md#message-header
[`nng_msg_header_append`]: /api/msg.md#append-or-insert-header
[`nng_msg_header_insert`]: /api/msg.md#append-or-insert-header
[`nng_msg_header_clear`]: /api/msg.md#clear-the-header
[`nng_msg_pipe`]: /api/msg.md#message-pipe
[`nng_url`]: /api/url.md#url-structure
[`nng_url_parse`]: /api/url.md#parse-a-url
[`nng_url_free`]: /api/url.md#destroy-a-url
[`nng_socket_pair`]: /api/misc.md#create-socket-pair
[`nng_random`]: /api/misc.md#get-random-number
[`nng_version`]: /api/misc.md#report-library-version
[`nng_mtx`]: /api/synch.md#mutual-exclusion-lock
[`nng_mtx_alloc`]: /api/synch.md#creating-a-mutex
[`nng_mtx_free`]: /api/synch.md#destroying-a-mutex
[`nng_mtx_lock`]: /api/synch.md#acquiring-a-mutex
[`nng_mtx_unlock`]: /api/synch.md#releasing-a-mutex
[`nng_cv`]: /api/synch.md#condition-variable
[`nng_cv_alloc`]: /api/synch.md#creating-a-condition-variable
[`nng_cv_free`]: /api/synch.md#destroy-a-condition-variable
[`nng_cv_until`]: /api/synch.md#waiting-for-the-condition
[`nng_cv_wait`]: /api/synch.md#waiting-for-the-condition
[`nng_cv_wake`]: /api/synch.md#signaling-the-condition
[`nng_cv_wake1`]: /api/synch.md#signaling-the-condition
[`nng_stat_type`]: /api/stats.md#statistic-type
[`nng_stats_free`]: /api/stats.md#freeing-a-snapshot
[`nng_stat_value`]: /api/stats.md#statistic-value
[`nng_stat_bool`]: /api/stats.md#statistic-value
[`nng_stat_string`]: /api/stats.md#statistic-value
[`nng_stat_unit`]: /api/stats.md#statistic-units
[`nng_id_set`]: /api/id_map.md#store-a-value
[`nng_send`]: /TODO.md
[`nng_recv`]: /TODO.md
[`nng_aio`]: /TODO.md
[`nng_sleep_aio`]: /TODO.md

<!-- Macros -->

[`NNG_ENOMEM`]: /api/errors.md#NNG_ENOMEM
[`NNG_ETIMEDOUT`]: /api/errors.md#NNG_ETIMEDOUT
[`NNG_ENOSPC`]: /api/errors.md#NNG_ENOSPC
[`NNG_ENOTSUP`]: /api/errors.md#NNG_ENOTSUP
[`NNG_ENOENT`]: /api/errors.md#NNG_ENOENT
[`NNG_DURATION_INFINITE`]: /api/time.md#duration-type
[`NNG_DURATION_DEFAULT`]: /api/time.md#duration-type
[`NNG_DURATION_ZERO`]: /api/time.md#duration-type
[`NNG_MAJOR_VERSION`]: /api/misc.md#report-library-version
[`NNG_MINOR_VERSION`]: /api/misc.md#report-library-version
[`NNG_PATCH_VERSION`]: /api/misc.md#report-library-version
[`NNG_STAT_ID`]: /api/stats.md#NNG_STAT_ID
[`NNG_STAT_COUNTER`]: /api/stats.md#NNG_STAT_COUNTER
[`NNG_STAT_LEVEL`]: /api/stats.md#NNG_STAT_LEVEL
[`NNG_STAT_SCOPE`]: /api/stats.md#NNG_STAT_SCOPE
[`NNG_STAT_STRING`]: /api/stats.md#NNG_STAT_STRING
[`NNG_STAT_BOOLEAN`]: /api/stats.md#NNG_STAT_BOOLEAN

<!-- Protocols -->

[bus]: /proto/bus.md
[pair]: /proto/pair.md
[pub]: /proto/pub.md
[sub]: /proto/sub.md
[pull]: /proto/pull.md
[push]: /proto/push.md
[req]: /proto/req.md
[rep]: /proto/rep.md
[surveyor]: /proto/surveyor.md
[respondent]: /proto/respondent.md

<!-- Transports -->

[socktran]: /tran/socket.md
[ipc]: /tran/ipc.md
[inproc]: /tran/inproc.md
[tcp]: /tran/tcp.md
[udp]: /tran/udp.md

<!-- Concept index -->

[aio]: /TODO.md
[raw]: /TODO.md
[pipe]: /TODO.md
[socket]: /TODO.md
[dialer]: /TODO.md
[listener]: /TODO.md
[message-body]: /api/msg.md#message-body
[message-header]: /api/msg.md#message-header
[synchronization]: /api/synch.md
[mutex]: /api/synch.md#mutual-exclusion-lock
[condvar]: /api/synch.md#condition-variable
[thread]: /api/thread.md
[statistic]: /api/stats.md
