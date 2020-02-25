#
# Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
# Copyright 2019 Devolutions <info@devolutions.net>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.

# We default to off here.
option(NNG_ENABLE_DOC "Enable building documentation." OFF)

if (NNG_ENABLE_DOC)
    find_program(ASCIIDOCTOR asciidoctor)
    if (NOT ASCIIDOCTOR)
        message(WARNING "Could not find asciidoctor: skipping docs")
        set(NNG_ENABLE_DOC OFF)
    else ()
        message(STATUS "Using asciidoctor at ${ASCIIDOCTOR}")
    endif ()
endif ()

if (NNG_ENABLE_DOC)
    set(NNG_DOCDIR ${CMAKE_CURRENT_SOURCE_DIR})

    set(NNG_A2M ${ASCIIDOCTOR} -b manpage -amanmanual='NNG Reference Manual')
    set(NNG_A2H ${ASCIIDOCTOR} -a nofooter -atoc=left -aicons=font -d manpage -b html5)

    macro(nng_man NAME SECT)

        add_custom_command(
                OUTPUT ${NAME}.${SECT}
                COMMAND ${NNG_A2M} -o ${NAME}.${SECT} ${NNG_DOCDIR}/${NAME}.${SECT}.adoc
                MAIN_DEPENDENCY ${NNG_DOCDIR}/${NAME}.${SECT}.adoc
        )

        add_custom_command(
                OUTPUT ${NAME}.${SECT}.html
                COMMAND ${NNG_A2H} -o ${NAME}.${SECT}.html ${NNG_DOCDIR}/${NAME}.${SECT}.adoc
                MAIN_DEPENDENCY ${NNG_DOCDIR}/${NAME}.${SECT}.adoc
        )

        set(NNG_MANS ${NNG_MANS} ${NAME}.${SECT})
        set(NNG_HTMLS ${NNG_HTMLS} ${NAME}.${SECT}.html)

        install(
                FILES ${CMAKE_CURRENT_BINARY_DIR}/${NAME}.${SECT}.html
                DESTINATION ${CMAKE_INSTALL_DOCDIR}
        )
        install(
                FILES ${CMAKE_CURRENT_BINARY_DIR}/${NAME}.${SECT}
                DESTINATION ${CMAKE_INSTALL_MANDIR}/man${SECT}
        )

    endmacro(nng_man)

    set(NNG_MAN1
            nngcat
            )

    set(NNG_MAN3
            libnng
            nng_aio_abort
            nng_aio_alloc
            nng_aio_begin
            nng_aio_cancel
            nng_aio_count
            nng_aio_defer
            nng_aio_finish
            nng_aio_free
            nng_aio_get_input
            nng_aio_get_msg
            nng_aio_get_output
            nng_aio_result
            nng_aio_set_input
            nng_aio_set_iov
            nng_aio_set_msg
            nng_aio_set_output
            nng_aio_set_timeout
            nng_aio_stop
            nng_aio_wait
            nng_alloc
            nng_bus_open
            nng_close
            nng_ctx_close
            nng_ctx_get
            nng_ctx_getopt
            nng_ctx_id
            nng_ctx_open
            nng_ctx_recv
            nng_ctx_send
            nng_ctx_set
            nng_ctx_setopt
            nng_device
            nng_dial
            nng_dialer_close
            nng_dialer_create
            nng_dialer_get
            nng_dialer_getopt
            nng_dialer_id
            nng_dialer_set
            nng_dialer_setopt
            nng_dialer_start
            nng_free
            nng_getopt
            nng_inproc_register
            nng_ipc_register
            nng_listen
            nng_listener_close
            nng_listener_create
            nng_listener_get
            nng_listener_getopt
            nng_listener_id
            nng_listener_set
            nng_listener_setopt
            nng_listener_start
            nng_msg_alloc
            nng_msg_append
            nng_msg_body
            nng_msg_chop
            nng_msg_clear
            nng_msg_dup
            nng_msg_free
            nng_msg_get_pipe
            nng_msg_header
            nng_msg_header_append
            nng_msg_header_chop
            nng_msg_header_clear
            nng_msg_header_insert
            nng_msg_header_len
            nng_msg_header_trim
            nng_msg_insert
            nng_msg_len
            nng_msg_realloc
            nng_msg_set_pipe
            nng_msg_trim
            nng_pair_open
            nng_pipe_close
            nng_pipe_dialer
            nng_pipe_get
            nng_pipe_getopt
            nng_pipe_id
            nng_pipe_listener
            nng_pipe_notify
            nng_pipe_socket
            nng_pub_open
            nng_pull_open
            nng_push_open
            nng_recv
            nng_recv_aio
            nng_recvmsg
            nng_rep_open
            nng_req_open
            nng_respondent_open
            nng_send
            nng_send_aio
            nng_sendmsg
            nng_setopt
            nng_sleep_aio
            nng_socket_id
            nng_socket_get
            nng_socket_set
            nng_stats_free
            nng_stats_get
            nng_stat_child
            nng_stat_desc
            nng_stat_find
            nng_stat_find_dialer
            nng_stat_find_listener
            nng_stat_find_socket
            nng_stat_name
            nng_stat_next
            nng_stat_string
            nng_stat_timestamp
            nng_stat_type
            nng_stat_unit
            nng_stat_value
            nng_strdup
            nng_strerror
            nng_strfree
            nng_sub_open
            nng_surveyor_open
            nng_tcp_register
            nng_tls_register
            nng_url_clone
            nng_url_free
            nng_url_parse
            nng_version
            nng_ws_register
            nng_wss_register
            nng_zt_register
            )

    set(NNG_MAN3COMPAT
            nn_allocmsg
            nn_bind
            nn_close
            nn_cmsg
            nn_connect
            nn_device
            nn_errno
            nn_freemsg
            nn_get_statistic
            nn_getsockopt
            nn_poll
            nn_reallocmsg
            nn_recv
            nn_recvmsg
            nn_send
            nn_sendmsg
            nn_setsockopt
            nn_shutdown
            nn_socket
            nn_strerror
            nn_term
            nng_compat
            )

    set(NNG_MAN3HTTP
            nng_http_client_alloc
            nng_http_client_connect
            nng_http_client_free
            nng_http_client_get_tls
            nng_http_client_set_tls
            nng_http_client_transact
            nng_http_conn_close
            nng_http_conn_read
            nng_http_conn_read_all
            nng_http_conn_read_req
            nng_http_conn_read_res
            nng_http_conn_transact
            nng_http_conn_write
            nng_http_conn_write_all
            nng_http_conn_write_req
            nng_http_conn_write_res
            nng_http_handler_alloc
            nng_http_handler_free
            nng_http_handler_get_data
            nng_http_handler_set_data
            nng_http_handler_set_host
            nng_http_handler_set_method
            nng_http_handler_set_tree
            nng_http_hijack
            nng_http_req_add_header
            nng_http_req_alloc
            nng_http_req_copy_data
            nng_http_req_del_header
            nng_http_req_free
            nng_http_req_get_data
            nng_http_req_get_header
            nng_http_req_get_method
            nng_http_req_get_uri
            nng_http_req_get_version
            nng_http_req_reset
            nng_http_req_set_data
            nng_http_req_set_header
            nng_http_req_set_method
            nng_http_req_set_uri
            nng_http_req_set_version
            nng_http_res_add_header
            nng_http_res_alloc
            nng_http_res_alloc_error
            nng_http_res_copy_data
            nng_http_res_del_header
            nng_http_res_free
            nng_http_res_get_data
            nng_http_res_get_header
            nng_http_res_get_reason
            nng_http_res_get_status
            nng_http_res_get_version
            nng_http_res_reset
            nng_http_res_set_data
            nng_http_res_set_header
            nng_http_res_set_reason
            nng_http_res_set_status
            nng_http_res_set_version
            nng_http_server_add_handler
            nng_http_server_del_handler
            nng_http_server_get_addr
            nng_http_server_get_tls
            nng_http_server_hold
            nng_http_server_release
            nng_http_server_set_tls
            nng_http_server_start
            nng_http_server_stop
            )

    set(NNG_MAN3SUPP
            nng_clock
            nng_cv_alloc
            nng_cv_free
            nng_cv_until
            nng_cv_wait
            nng_cv_wake
            nng_cv_wake1
            nng_msleep
            nng_mtx_alloc
            nng_mtx_free
            nng_mtx_lock
            nng_mtx_unlock
            nng_opts_parse
            nng_random
            nng_thread_create
            nng_thread_destroy
            )

    set(NNG_MAN3STR
            nng_stream_close
            nng_stream_free
            nng_stream_get
            nng_stream_recv
            nng_stream_send
            nng_stream_set
            nng_stream_dialer_alloc
            nng_stream_dialer_close
            nng_stream_dialer_dial
            nng_stream_dialer_free
            nng_stream_dialer_get
            nng_stream_dialer_set
            nng_stream_listener_accept
            nng_stream_listener_alloc
            nng_stream_listener_close
            nng_stream_listener_free
            nng_stream_listener_get
            nng_stream_listener_listen
            nng_stream_listener_set
            )

    set(NNG_MAN3TLS
            nng_tls_config_alloc
            nng_tls_config_auth_mode
            nng_tls_config_ca_chain
            nng_tls_config_ca_file
            nng_tls_config_cert_key_file
            nng_tls_config_free
            nng_tls_config_hold
            nng_tls_config_own_cert
            nng_tls_config_server_name
            nng_tls_engine_description
            nng_tls_engine_fips_mode
            nng_tls_engine_name
            )

    set(NNG_MAN5
            nng_aio
            nng_ctx
            nng_dialer
            nng_duration
            nng_iov
            nng_listener
            nng_msg
            nng_options
            nng_pipe
            nng_sockaddr
            nng_sockaddr_in
            nng_sockaddr_in6
            nng_sockaddr_inproc
            nng_sockaddr_ipc
            nng_sockaddr_zt
            nng_socket
            nng_stat

            nng_stream
            nng_stream_dialer
            nng_stream_listener

            nng_tcp_options
            nng_ipc_options
            nng_tls_config
            nng_tls_engine
            nng_tls_options
            )

    set(NNG_MAN7
            nng
            nng_bus
            nng_inproc
            nng_ipc
            nng_pair
            nng_pub
            nng_pull
            nng_push
            nng_rep
            nng_req
            nng_respondent
            nng_sub
            nng_surveyor
            nng_tcp
            nng_tls
            nng_ws
            nng_zerotier
            )

    foreach (F ${NNG_MAN1})
        nng_man(${F} 1)
    endforeach ()

    foreach (F ${NNG_MAN3})
        nng_man(${F} 3)
    endforeach ()

    foreach (F ${NNG_MAN3COMPAT})
        nng_man(${F} 3compat)
    endforeach ()

    foreach (F ${NNG_MAN3HTTP})
        nng_man(${F} 3http)
    endforeach ()

    foreach (F ${NNG_MAN3STR})
        nng_man(${F} 3str)
    endforeach ()

    foreach (F ${NNG_MAN3SUPP})
        nng_man(${F} 3supp)
    endforeach ()

    foreach (F ${NNG_MAN3TLS})
        nng_man(${F} 3tls)
    endforeach ()

    foreach (F ${NNG_MAN5})
        nng_man(${F} 5)
    endforeach ()

    foreach (F ${NNG_MAN7})
        nng_man(${F} 7)
    endforeach ()

    add_custom_target(man ALL DEPENDS ${NNG_MANS})
    add_custom_target(html ALL DEPENDS ${NNG_HTMLS})
endif ()
