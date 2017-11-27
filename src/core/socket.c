//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include <stdio.h>
#include <string.h>

// Socket implementation.

static nni_list    nni_sock_list;
static nni_idhash *nni_sock_hash;
static nni_mtx     nni_sock_lk;

typedef struct nni_socket_option {
	const char *so_name;
	int (*so_getopt)(nni_sock *, void *, size_t *);
	int (*so_setopt)(nni_sock *, const void *, size_t);
} nni_socket_option;

typedef struct nni_sockopt {
	nni_list_node node;
	char *        name;
	size_t        sz;
	void *        data;
} nni_sockopt;

struct nni_socket {
	nni_list_node s_node;
	nni_mtx       s_mx;
	nni_cv        s_cv;
	nni_cv        s_close_cv;
	int           s_raw;

	uint64_t s_id;
	uint32_t s_flags;
	unsigned s_refcnt; // protected by global lock
	void *   s_data;   // Protocol private

	nni_msgq *s_uwq; // Upper write queue
	nni_msgq *s_urq; // Upper read queue

	nni_proto_id s_self_id;
	nni_proto_id s_peer_id;

	nni_proto_pipe_ops s_pipe_ops;
	nni_proto_sock_ops s_sock_ops;

	// options
	nni_duration s_linger;    // linger time
	nni_duration s_sndtimeo;  // send timeout
	nni_duration s_rcvtimeo;  // receive timeout
	nni_duration s_reconn;    // reconnect time
	nni_duration s_reconnmax; // max reconnect time
	size_t       s_rcvmaxsz;  // max receive size
	nni_list     s_options;   // opts not handled by sock/proto
	char         s_name[64];  // socket name (legacy compat)

	nni_list s_eps;   // active endpoints
	nni_list s_pipes; // active pipes

	int s_ep_pend; // EP dial/listen in progress
	int s_closing; // Socket is closing
	int s_closed;  // Socket closed, protected by global lock

	nni_notifyfd s_send_fd;
	nni_notifyfd s_recv_fd;
};

static void
nni_sock_can_send_cb(void *arg, int flags)
{
	nni_notifyfd *fd = arg;

	if ((flags & nni_msgq_f_can_put) == 0) {
		nni_plat_pipe_clear(fd->sn_rfd);
	} else {
		nni_plat_pipe_raise(fd->sn_wfd);
	}
}

static void
nni_sock_can_recv_cb(void *arg, int flags)
{
	nni_notifyfd *fd = arg;

	if ((flags & nni_msgq_f_can_get) == 0) {
		nni_plat_pipe_clear(fd->sn_rfd);
	} else {
		nni_plat_pipe_raise(fd->sn_wfd);
	}
}

static int
nni_sock_getopt_fd(nni_sock *s, int flag, void *val, size_t *szp)
{
	int           rv;
	nni_notifyfd *fd;
	nni_msgq *    mq;
	nni_msgq_cb   cb;

	if ((*szp < sizeof(int))) {
		return (NNG_EINVAL);
	}

	if ((flag & nni_sock_flags(s)) == 0) {
		return (NNG_ENOTSUP);
	}

	switch (flag) {
	case NNI_PROTO_FLAG_SND:
		fd = &s->s_send_fd;
		mq = s->s_uwq;
		cb = nni_sock_can_send_cb;
		break;
	case NNI_PROTO_FLAG_RCV:
		fd = &s->s_recv_fd;
		mq = s->s_urq;
		cb = nni_sock_can_recv_cb;
		break;
	default:
		nni_panic("default case!");
	}

	// If we already inited this, just give back the same file descriptor.
	if (fd->sn_init) {
		memcpy(val, &fd->sn_rfd, sizeof(int));
		*szp = sizeof(int);
		return (0);
	}

	if ((rv = nni_plat_pipe_open(&fd->sn_wfd, &fd->sn_rfd)) != 0) {
		return (rv);
	}

	nni_msgq_set_cb(mq, cb, fd);

	fd->sn_init = 1;
	*szp        = sizeof(int);
	memcpy(val, &fd->sn_rfd, sizeof(int));
	return (0);
}

static int
nni_sock_getopt_sendfd(nni_sock *s, void *buf, size_t *szp)
{
	return (nni_sock_getopt_fd(s, NNI_PROTO_FLAG_SND, buf, szp));
}

static int
nni_sock_getopt_recvfd(nni_sock *s, void *buf, size_t *szp)
{
	return (nni_sock_getopt_fd(s, NNI_PROTO_FLAG_RCV, buf, szp));
}

static int
nni_sock_setopt_recvtimeo(nni_sock *s, const void *buf, size_t sz)
{
	return (nni_setopt_ms(&s->s_rcvtimeo, buf, sz));
}

static int
nni_sock_getopt_recvtimeo(nni_sock *s, void *buf, size_t *szp)
{
	return (nni_getopt_ms(s->s_rcvtimeo, buf, szp));
}

static int
nni_sock_setopt_sendtimeo(nni_sock *s, const void *buf, size_t sz)
{
	return (nni_setopt_ms(&s->s_sndtimeo, buf, sz));
}

static int
nni_sock_getopt_sendtimeo(nni_sock *s, void *buf, size_t *szp)
{
	return (nni_getopt_ms(s->s_sndtimeo, buf, szp));
}

static int
nni_sock_setopt_reconnmint(nni_sock *s, const void *buf, size_t sz)
{
	return (nni_setopt_ms(&s->s_reconn, buf, sz));
}

static int
nni_sock_getopt_reconnmint(nni_sock *s, void *buf, size_t *szp)
{
	return (nni_getopt_ms(s->s_reconn, buf, szp));
}

static int
nni_sock_setopt_reconnmaxt(nni_sock *s, const void *buf, size_t sz)
{
	return (nni_setopt_ms(&s->s_reconnmax, buf, sz));
}

static int
nni_sock_getopt_reconnmaxt(nni_sock *s, void *buf, size_t *szp)
{
	return (nni_getopt_ms(s->s_reconnmax, buf, szp));
}

static int
nni_sock_setopt_recvbuf(nni_sock *s, const void *buf, size_t sz)
{
	return (nni_setopt_buf(s->s_urq, buf, sz));
}

static int
nni_sock_getopt_recvbuf(nni_sock *s, void *buf, size_t *szp)
{
	return (nni_getopt_buf(s->s_urq, buf, szp));
}

static int
nni_sock_setopt_sendbuf(nni_sock *s, const void *buf, size_t sz)
{
	return (nni_setopt_buf(s->s_uwq, buf, sz));
}

static int
nni_sock_getopt_sendbuf(nni_sock *s, void *buf, size_t *szp)
{
	return (nni_getopt_buf(s->s_uwq, buf, szp));
}

static int
nni_sock_getopt_sockname(nni_sock *s, void *buf, size_t *szp)
{
	return (nni_getopt_str(s->s_name, buf, szp));
}

static int
nni_sock_setopt_sockname(nni_sock *s, const void *buf, size_t sz)
{
	if (nni_strnlen(buf, sz) > sizeof(s->s_name) - 1) {
		return (NNG_EINVAL);
	}
	nni_strlcpy(s->s_name, buf, sizeof(s->s_name));
	return (0);
}

static int
nni_sock_getopt_domain(nni_sock *s, void *buf, size_t *szp)
{
	return (nni_getopt_int(s->s_raw + 1, buf, szp));
}

static const nni_socket_option nni_sock_options[] = {
	{
	    .so_name   = NNG_OPT_RECVTIMEO,
	    .so_getopt = nni_sock_getopt_recvtimeo,
	    .so_setopt = nni_sock_setopt_recvtimeo,
	},
	{
	    .so_name   = NNG_OPT_SENDTIMEO,
	    .so_getopt = nni_sock_getopt_sendtimeo,
	    .so_setopt = nni_sock_setopt_sendtimeo,
	},
	{
	    .so_name   = NNG_OPT_RECVFD,
	    .so_getopt = nni_sock_getopt_recvfd,
	    .so_setopt = NULL,
	},
	{
	    .so_name   = NNG_OPT_SENDFD,
	    .so_getopt = nni_sock_getopt_sendfd,
	    .so_setopt = NULL,
	},
	{
	    .so_name   = NNG_OPT_RECVBUF,
	    .so_getopt = nni_sock_getopt_recvbuf,
	    .so_setopt = nni_sock_setopt_recvbuf,
	},
	{
	    .so_name   = NNG_OPT_SENDBUF,
	    .so_getopt = nni_sock_getopt_sendbuf,
	    .so_setopt = nni_sock_setopt_sendbuf,
	},
	{
	    .so_name   = NNG_OPT_RECONNMINT,
	    .so_getopt = nni_sock_getopt_reconnmint,
	    .so_setopt = nni_sock_setopt_reconnmint,
	},
	{
	    .so_name   = NNG_OPT_RECONNMAXT,
	    .so_getopt = nni_sock_getopt_reconnmaxt,
	    .so_setopt = nni_sock_setopt_reconnmaxt,
	},
	{
	    .so_name   = NNG_OPT_SOCKNAME,
	    .so_getopt = nni_sock_getopt_sockname,
	    .so_setopt = nni_sock_setopt_sockname,
	},
	{
	    .so_name   = NNG_OPT_DOMAIN,
	    .so_getopt = nni_sock_getopt_domain,
	    .so_setopt = NULL,
	},
	// terminate list
	{ NULL, NULL, NULL },
};

static void
nni_free_opt(nni_sockopt *opt)
{
	nni_strfree(opt->name);
	nni_free(opt->data, opt->sz);
	NNI_FREE_STRUCT(opt);
}

uint32_t
nni_sock_id(nni_sock *s)
{
	return ((uint32_t) s->s_id);
}

// nni_sock_sendq and nni_sock_recvq are called by the protocol to obtain
// the upper read and write queues.
nni_msgq *
nni_sock_sendq(nni_sock *s)
{
	return (s->s_uwq);
}

nni_msgq *
nni_sock_recvq(nni_sock *s)
{
	return (s->s_urq);
}

int
nni_sock_find(nni_sock **sockp, uint32_t id)
{
	int       rv;
	nni_sock *s;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	nni_mtx_lock(&nni_sock_lk);
	if ((rv = nni_idhash_find(nni_sock_hash, id, (void **) &s)) == 0) {
		if (s->s_closed) {
			rv = NNG_ECLOSED;
		} else {
			s->s_refcnt++;
			*sockp = s;
		}
	}
	nni_mtx_unlock(&nni_sock_lk);

	if (rv == NNG_ENOENT) {
		rv = NNG_ECLOSED;
	}

	return (rv);
}

void
nni_sock_rele(nni_sock *s)
{
	nni_mtx_lock(&nni_sock_lk);
	s->s_refcnt--;
	if (s->s_closed && (s->s_refcnt < 2)) {
		nni_cv_wake(&s->s_close_cv);
	}
	nni_mtx_unlock(&nni_sock_lk);
}

int
nni_sock_pipe_start(nni_sock *s, nni_pipe *pipe)
{
	void *pdata = nni_pipe_get_proto_data(pipe);
	int   rv;

	NNI_ASSERT(s != NULL);
	nni_mtx_lock(&s->s_mx);
	if (s->s_closing) {
		// We're closing, bail out.
		rv = NNG_ECLOSED;
	} else if (nni_pipe_peer(pipe) != s->s_peer_id.p_id) {
		// Peer protocol mismatch.
		rv = NNG_EPROTO;
	} else {
		// Protocol can reject for other reasons.
		rv = s->s_pipe_ops.pipe_start(pdata);
	}
	nni_mtx_unlock(&s->s_mx);
	return (rv);
}

int
nni_sock_pipe_add(nni_sock *s, nni_pipe *p)
{
	int   rv;
	void *pdata;

	if ((rv = s->s_pipe_ops.pipe_init(&pdata, p, s->s_data)) != 0) {
		return (rv);
	}
	nni_pipe_set_proto_data(p, pdata);

	// Initialize protocol pipe data.
	nni_mtx_lock(&s->s_mx);
	if (s->s_closing) {
		nni_mtx_unlock(&s->s_mx);
		return (NNG_ECLOSED);
	}

	nni_list_append(&s->s_pipes, p);

	// Start the initial negotiation I/O...
	nni_pipe_start(p);

	nni_mtx_unlock(&s->s_mx);
	return (0);
}

void
nni_sock_pipe_remove(nni_sock *sock, nni_pipe *pipe)
{
	void *pdata;

	nni_mtx_lock(&sock->s_mx);
	pdata = nni_pipe_get_proto_data(pipe);
	if (pdata != NULL) {
		sock->s_pipe_ops.pipe_stop(pdata);
		nni_pipe_set_proto_data(pipe, NULL);
		if (nni_list_active(&sock->s_pipes, pipe)) {
			nni_list_remove(&sock->s_pipes, pipe);
		}
		sock->s_pipe_ops.pipe_fini(pdata);
	}
	if (sock->s_closing && nni_list_empty(&sock->s_pipes)) {
		nni_cv_wake(&sock->s_cv);
	}
	nni_mtx_unlock(&sock->s_mx);
}

static void
nni_sock_destroy(nni_sock *s)
{
	nni_sockopt *sopt;

	// Close any open notification pipes.
	if (s->s_recv_fd.sn_init) {
		nni_plat_pipe_close(s->s_recv_fd.sn_wfd, s->s_recv_fd.sn_rfd);
	}
	if (s->s_send_fd.sn_init) {
		nni_plat_pipe_close(s->s_send_fd.sn_wfd, s->s_send_fd.sn_rfd);
	}

	// The protocol needs to clean up its state.
	if (s->s_data != NULL) {
		s->s_sock_ops.sock_fini(s->s_data);
	}

	while ((sopt = nni_list_first(&s->s_options)) != NULL) {
		nni_list_remove(&s->s_options, sopt);
		nni_free_opt(sopt);
	}

	// This exists to silence a false positive in helgrind.
	nni_mtx_lock(&s->s_mx);
	nni_mtx_unlock(&s->s_mx);

	nni_msgq_fini(s->s_urq);
	nni_msgq_fini(s->s_uwq);
	nni_cv_fini(&s->s_close_cv);
	nni_cv_fini(&s->s_cv);
	nni_mtx_fini(&s->s_mx);
	NNI_FREE_STRUCT(s);
}

static int
nni_sock_create(nni_sock **sp, const nni_proto *proto)
{
	int       rv;
	nni_sock *s;

	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}
	s->s_linger          = 0;
	s->s_sndtimeo        = -1;
	s->s_rcvtimeo        = -1;
	s->s_closing         = 0;
	s->s_reconn          = NNI_SECOND;
	s->s_reconnmax       = 0;
	s->s_rcvmaxsz        = 1024 * 1024; // 1 MB by default
	s->s_id              = 0;
	s->s_refcnt          = 0;
	s->s_send_fd.sn_init = 0;
	s->s_recv_fd.sn_init = 0;
	s->s_self_id         = proto->proto_self;
	s->s_peer_id         = proto->proto_peer;
	s->s_flags           = proto->proto_flags;
	s->s_sock_ops        = *proto->proto_sock_ops;
	s->s_pipe_ops        = *proto->proto_pipe_ops;

	NNI_ASSERT(s->s_sock_ops.sock_open != NULL);
	NNI_ASSERT(s->s_sock_ops.sock_close != NULL);

	NNI_ASSERT(s->s_pipe_ops.pipe_start != NULL);
	NNI_ASSERT(s->s_pipe_ops.pipe_stop != NULL);

	NNI_LIST_NODE_INIT(&s->s_node);
	NNI_LIST_INIT(&s->s_options, nni_sockopt, node);
	nni_pipe_sock_list_init(&s->s_pipes);
	nni_ep_list_init(&s->s_eps);
	nni_mtx_init(&s->s_mx);
	nni_cv_init(&s->s_cv, &s->s_mx);
	nni_cv_init(&s->s_close_cv, &nni_sock_lk);

	if (((rv = nni_msgq_init(&s->s_uwq, 0)) != 0) ||
	    ((rv = nni_msgq_init(&s->s_urq, 0)) != 0) ||
	    ((rv = s->s_sock_ops.sock_init(&s->s_data, s)) != 0) ||
	    ((rv = nni_sock_setopt(s, NNG_OPT_LINGER, &s->s_linger,
	          sizeof(nni_duration))) != 0) ||
	    ((rv = nni_sock_setopt(s, NNG_OPT_SENDTIMEO, &s->s_sndtimeo,
	          sizeof(nni_duration))) != 0) ||
	    ((rv = nni_sock_setopt(s, NNG_OPT_RECVTIMEO, &s->s_rcvtimeo,
	          sizeof(nni_duration))) != 0) ||
	    ((rv = nni_sock_setopt(s, NNG_OPT_RECONNMINT, &s->s_reconn,
	          sizeof(nni_duration))) != 0) ||
	    ((rv = nni_sock_setopt(s, NNG_OPT_RECONNMAXT, &s->s_reconnmax,
	          sizeof(nni_duration))) != 0) ||
	    ((rv = nni_sock_setopt(s, NNG_OPT_RECVMAXSZ, &s->s_rcvmaxsz,
	          sizeof(size_t))) != 0)) {
		nni_sock_destroy(s);
		return (rv);
	}

	if (s->s_sock_ops.sock_filter != NULL) {
		nni_msgq_set_filter(
		    s->s_urq, s->s_sock_ops.sock_filter, s->s_data);
	}

	*sp = s;
	return (rv);
}

int
nni_sock_sys_init(void)
{
	int rv;

	NNI_LIST_INIT(&nni_sock_list, nni_sock, s_node);
	nni_mtx_init(&nni_sock_lk);

	if ((rv = nni_idhash_init(&nni_sock_hash)) != 0) {
		nni_sock_sys_fini();
	} else {
		nni_idhash_set_limits(nni_sock_hash, 1, 0x7fffffff, 1);
	}
	return (rv);
}

void
nni_sock_sys_fini(void)
{
	nni_idhash_fini(nni_sock_hash);
	nni_sock_hash = NULL;
	nni_mtx_fini(&nni_sock_lk);
}

int
nni_sock_open(nni_sock **sockp, const nni_proto *proto)
{
	nni_sock *s = NULL;
	int       rv;

	if (proto->proto_version != NNI_PROTOCOL_VERSION) {
		// unsupported protocol version
		return (NNG_ENOTSUP);
	}

	if (((rv = nni_init()) != 0) ||
	    ((rv = nni_sock_create(&s, proto)) != 0)) {
		return (rv);
	}

	nni_mtx_lock(&nni_sock_lk);
	if ((rv = nni_idhash_alloc(nni_sock_hash, &s->s_id, s)) != 0) {
		nni_sock_destroy(s);
	} else {
		nni_list_append(&nni_sock_list, s);
		s->s_sock_ops.sock_open(s->s_data);
		*sockp = s;
	}
	// Set the sockname.
	(void) snprintf(
	    s->s_name, sizeof(s->s_name), "%u", (unsigned) s->s_id);
	nni_mtx_unlock(&nni_sock_lk);

	return (rv);
}

// nni_sock_shutdown shuts down the socket; after this point no further
// access to the socket will function, and any threads blocked in entry
// points will be woken (and the functions they are blocked in will return
// NNG_ECLOSED.)
int
nni_sock_shutdown(nni_sock *sock)
{
	nni_pipe *pipe;
	nni_ep *  ep;
	nni_ep *  nep;
	nni_time  linger;

	nni_mtx_lock(&sock->s_mx);
	if (sock->s_closing) {
		nni_mtx_unlock(&sock->s_mx);
		return (NNG_ECLOSED);
	}
	// Mark us closing, so no more EPs or changes can occur.
	sock->s_closing = 1;

	// Special optimization; if there are no pipes connected,
	// then there is no reason to linger since there's nothing that
	// could possibly send this data out.
	if (nni_list_first(&sock->s_pipes) == NULL) {
		linger = NNI_TIME_ZERO;
	} else {
		linger = nni_clock() + sock->s_linger;
	}

	// Close the EPs. This prevents new connections from forming but
	// but allows existing ones to drain.
	NNI_LIST_FOREACH (&sock->s_eps, ep) {
		nni_ep_shutdown(ep);
	}
	nni_mtx_unlock(&sock->s_mx);

	// We drain the upper write queue.  This is just like closing it,
	// except that the protocol gets a chance to get the messages and
	// push them down to the transport.  This operation can *block*
	// until the linger time has expired.
	nni_msgq_drain(sock->s_uwq, linger);

	// Generally, unless the protocol is blocked trying to perform
	// writes (e.g. a slow reader on the other side), it should be
	// trying to shut things down.  We wait to give it
	// a chance to do so gracefully.
	nni_mtx_lock(&sock->s_mx);
	while (nni_list_first(&sock->s_pipes) != NULL) {
		if (nni_cv_until(&sock->s_cv, linger) == NNG_ETIMEDOUT) {
			break;
		}
	}

	// At this point, we've done everything we politely can to give
	// the protocol a chance to flush its write side.  Now its time
	// to be a little more insistent.

	// Close the upper queues immediately.  This can happen
	// safely while we hold the lock.
	nni_msgq_close(sock->s_urq);
	nni_msgq_close(sock->s_uwq);

	// Go through the endpoint list, attempting to close them.
	// We might already have a close in progress, in which case
	// we skip past it; it will be removed from another thread.
	nep = nni_list_first(&sock->s_eps);
	while ((ep = nep) != NULL) {
		nep = nni_list_next(&sock->s_eps, nep);

		if (nni_ep_hold(ep) == 0) {
			nni_mtx_unlock(&sock->s_mx);
			nni_ep_close(ep);
			nni_mtx_lock(&sock->s_mx);
		}
	}

	// For each pipe, arrange for it to teardown hard.
	NNI_LIST_FOREACH (&sock->s_pipes, pipe) {
		nni_pipe_stop(pipe);
	}

	// We have to wait for *both* endpoints and pipes to be removed.
	while ((!nni_list_empty(&sock->s_pipes)) ||
	    (!nni_list_empty(&sock->s_eps))) {
		nni_cv_wait(&sock->s_cv);
	}

	sock->s_sock_ops.sock_close(sock->s_data);

	nni_cv_wake(&sock->s_cv);

	NNI_ASSERT(nni_list_first(&sock->s_pipes) == NULL);

	nni_mtx_unlock(&sock->s_mx);

	// At this point, there are no threads blocked inside of us
	// that are referencing socket state.  User code should call
	// nng_close to release the last resources.
	return (0);
}

// nni_sock_close shuts down the socket, then releases any resources
// associated with it.  It is a programmer error to reference the socket
// after this function is called, as the pointer may reference invalid
// memory or other objects.
void
nni_sock_close(nni_sock *s)
{
	// Shutdown everything if not already done.  This operation
	// is idempotent.
	nni_sock_shutdown(s);

	nni_mtx_lock(&nni_sock_lk);
	if (s->s_closed) {
		// Some other thread called close.  All we need to do is
		// drop our reference count.
		nni_mtx_unlock(&nni_sock_lk);
		nni_sock_rele(s);
		return;
	}
	s->s_closed = 1;
	nni_idhash_remove(nni_sock_hash, s->s_id);

	// We might have been removed from the list already, e.g. by
	// nni_sock_closeall.  This is idempotent.
	nni_list_node_remove(&s->s_node);

	// Wait for all other references to drop.  Note that we
	// have a reference already (from our caller).
	while (s->s_refcnt > 1) {
		nni_cv_wait(&s->s_close_cv);
	}
	nni_mtx_unlock(&nni_sock_lk);

	// Wait for pipe and eps to finish closing.
	nni_mtx_lock(&s->s_mx);
	while (
	    (!nni_list_empty(&s->s_pipes)) || (!nni_list_empty(&s->s_eps))) {
		nni_cv_wait(&s->s_cv);
	}
	nni_mtx_unlock(&s->s_mx);

	nni_sock_destroy(s);
}

void
nni_sock_closeall(void)
{
	nni_sock *s;

	if (nni_sock_hash == NULL) {
		return;
	}
	for (;;) {
		nni_mtx_lock(&nni_sock_lk);
		if ((s = nni_list_first(&nni_sock_list)) == NULL) {
			nni_mtx_unlock(&nni_sock_lk);
			return;
		}
		// Bump the reference count.  The close call below will
		// drop it.
		s->s_refcnt++;
		nni_list_node_remove(&s->s_node);
		nni_mtx_unlock(&nni_sock_lk);
		nni_sock_close(s);
	}
}

static void
nni_sock_normalize_expiration(nni_aio *aio, nni_duration def)
{
	if (aio->a_timeout == (nni_duration) -2) {
		aio->a_timeout = def;
	}
}

void
nni_sock_send(nni_sock *sock, nni_aio *aio)
{
	nni_sock_normalize_expiration(aio, sock->s_sndtimeo);
	sock->s_sock_ops.sock_send(sock->s_data, aio);
}

void
nni_sock_recv(nni_sock *sock, nni_aio *aio)
{
	nni_sock_normalize_expiration(aio, sock->s_rcvtimeo);
	sock->s_sock_ops.sock_recv(sock->s_data, aio);
}

// nni_sock_protocol returns the socket's 16-bit protocol number.
uint16_t
nni_sock_proto(nni_sock *sock)
{
	return (sock->s_self_id.p_id);
}

uint16_t
nni_sock_peer(nni_sock *sock)
{
	return (sock->s_peer_id.p_id);
}

const char *
nni_sock_proto_name(nni_sock *sock)
{
	return (sock->s_self_id.p_name);
}

const char *
nni_sock_peer_name(nni_sock *sock)
{
	return (sock->s_peer_id.p_name);
}

void
nni_sock_reconntimes(nni_sock *sock, nni_duration *rcur, nni_duration *rmax)
{
	// These two values are linked, so get them atomically.
	nni_mtx_lock(&sock->s_mx);
	*rcur = sock->s_reconn;
	*rmax = sock->s_reconnmax ? sock->s_reconnmax : sock->s_reconn;
	nni_mtx_unlock(&sock->s_mx);
}

int
nni_sock_ep_add(nni_sock *s, nni_ep *ep)
{
	nni_sockopt *sopt;

	nni_mtx_lock(&s->s_mx);
	if (s->s_closing) {
		nni_mtx_unlock(&s->s_mx);
		return (NNG_ECLOSED);
	}

	NNI_LIST_FOREACH (&s->s_options, sopt) {
		int rv;
		rv = nni_ep_setopt(ep, sopt->name, sopt->data, sopt->sz);
		if ((rv != 0) && (rv != NNG_ENOTSUP)) {
			nni_mtx_unlock(&s->s_mx);
			return (rv);
		}
	}

	nni_list_append(&s->s_eps, ep);
	nni_mtx_unlock(&s->s_mx);
	return (0);
}

void
nni_sock_ep_remove(nni_sock *sock, nni_ep *ep)
{
	nni_mtx_lock(&sock->s_mx);
	if (nni_list_active(&sock->s_eps, ep)) {
		nni_list_remove(&sock->s_eps, ep);
		if ((sock->s_closing) && (nni_list_empty(&sock->s_eps))) {
			nni_cv_wake(&sock->s_cv);
		}
	}
	nni_mtx_unlock(&sock->s_mx);
}

int
nni_sock_setopt(nni_sock *s, const char *name, const void *val, size_t size)
{
	int                          rv = NNG_ENOTSUP;
	nni_ep *                     ep;
	int                          commits = 0;
	nni_sockopt *                optv;
	nni_sockopt *                oldv = NULL;
	const nni_socket_option *    sso;
	const nni_proto_sock_option *pso;

	nni_mtx_lock(&s->s_mx);
	if (s->s_closing) {
		nni_mtx_unlock(&s->s_mx);
		return (NNG_ECLOSED);
	}

	// Protocol options.
	for (pso = s->s_sock_ops.sock_options; pso->pso_name != NULL; pso++) {
		if (strcmp(pso->pso_name, name) != 0) {
			continue;
		}
		if (pso->pso_setopt == NULL) {
			nni_mtx_unlock(&s->s_mx);
			return (NNG_EREADONLY);
		}
		rv = pso->pso_setopt(s->s_data, val, size);
		if ((rv == 0) && (strcmp(name, NNG_OPT_RAW) == 0) &&
		    (size >= sizeof(int))) {
			// Save the raw option -- we use this for the DOMAIN.
			memcpy(&s->s_raw, val, sizeof(int));
		}
		nni_mtx_unlock(&s->s_mx);
		return (rv);
	}

	// Some options do not go down to transports.  Handle them directly.
	for (sso = nni_sock_options; sso->so_name != NULL; sso++) {
		if (strcmp(sso->so_name, name) != 0) {
			continue;
		}
		if (sso->so_setopt == NULL) {
			nni_mtx_unlock(&s->s_mx);
			return (NNG_EREADONLY);
		}
		rv = sso->so_setopt(s, val, size);
		nni_mtx_unlock(&s->s_mx);
		return (rv);
	}

	nni_mtx_unlock(&s->s_mx);

	// If the option was already handled one way or the other,
	if (rv != NNG_ENOTSUP) {
		return (rv);
	}

	// Validation of transport options.  This is stateless, so transports
	// should not fail to set an option later if they passed it here.
	rv = nni_tran_chkopt(name, val, size);

	// Also check a few generic things.  We do this if no transport
	// was found, or even if a transport rejected one of the settings.
	if ((rv == NNG_ENOTSUP) || (rv == 0)) {
		if ((strcmp(name, NNG_OPT_LINGER) == 0)) {
			rv = nni_chkopt_ms(val, size);
		} else if (strcmp(name, NNG_OPT_RECVMAXSZ) == 0) {
			// just a sanity test on the size; it also ensures that
			// a size can be set even with no transport configured.
			rv = nni_chkopt_size(val, size, 0, NNI_MAXSZ);
		}
	}

	if (rv != 0) {
		return (rv);
	}

	// Prepare a copy of the sockoption.
	if ((optv = NNI_ALLOC_STRUCT(optv)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((optv->data = nni_alloc(size)) == NULL) {
		NNI_FREE_STRUCT(optv);
		return (NNG_ENOMEM);
	}
	if ((optv->name = nni_strdup(name)) == NULL) {
		nni_free(optv->data, size);
		NNI_FREE_STRUCT(optv);
		return (NNG_ENOMEM);
	}
	memcpy(optv->data, val, size);
	optv->sz = size;
	NNI_LIST_NODE_INIT(&optv->node);

	nni_mtx_lock(&s->s_mx);
	NNI_LIST_FOREACH (&s->s_options, oldv) {
		if (strcmp(oldv->name, name) == 0) {
			if ((oldv->sz != size) ||
			    (memcmp(oldv->data, val, size) != 0)) {
				break;
			}

			// The values are the same.  This is a no-op.
			nni_mtx_unlock(&s->s_mx);
			nni_free_opt(optv);
			return (0);
		}
	}

	// Apply the options.  Failure to set any option on any transport
	// (other than ENOTSUP) stops the operation altogether.  Its
	// important that transport wide checks properly pre-validate.
	NNI_LIST_FOREACH (&s->s_eps, ep) {
		int x;
		x = nni_ep_setopt(ep, optv->name, optv->data, size);
		if (x != NNG_ENOTSUP) {
			if ((rv = x) != 0) {
				nni_mtx_unlock(&s->s_mx);
				nni_free_opt(optv);
				return (rv);
			}
		}
	}

	// For some options, which also have an impact on the socket
	// behavior, we save a local value.  Note that the transport
	// will already have had a chance to veto this.

	if (strcmp(name, NNG_OPT_LINGER) == 0) {
		rv = nni_setopt_ms(&s->s_linger, val, size);
	}

	if (rv == 0) {
		// Remove and toss the old value, we are using a new one.
		if (oldv != NULL) {
			nni_list_remove(&s->s_options, oldv);
			nni_free_opt(oldv);
		}

		// Insert our new value.  This permits it to be compared
		// against later, and for new endpoints to automatically
		// receive these values,
		nni_list_append(&s->s_options, optv);
	} else {
		nni_free_opt(optv);
	}

	nni_mtx_unlock(&s->s_mx);
	return (rv);
}

int
nni_sock_getopt(nni_sock *s, const char *name, void *val, size_t *szp)
{
	int                          rv = NNG_ENOTSUP;
	nni_sockopt *                sopt;
	const nni_socket_option *    sso;
	const nni_proto_sock_option *pso;

	nni_mtx_lock(&s->s_mx);
	if (s->s_closing) {
		nni_mtx_unlock(&s->s_mx);
		return (NNG_ECLOSED);
	}

	// Protocol specific options.
	for (pso = s->s_sock_ops.sock_options; pso->pso_name != NULL; pso++) {
		if (strcmp(name, pso->pso_name) != 0) {
			continue;
		}
		if (pso->pso_getopt == NULL) {
			nni_mtx_unlock(&s->s_mx);
			return (NNG_EWRITEONLY);
		}
		rv = pso->pso_getopt(s->s_data, val, szp);
		nni_mtx_unlock(&s->s_mx);
		return (rv);
	}

	// Options that are handled by socket core, and never passed down.
	for (sso = nni_sock_options; sso->so_name != NULL; sso++) {
		if (strcmp(name, sso->so_name) != 0) {
			continue;
		}
		if (sso->so_getopt == NULL) {
			nni_mtx_unlock(&s->s_mx);
			return (NNG_EWRITEONLY);
		}
		rv = sso->so_getopt(s, val, szp);
		nni_mtx_unlock(&s->s_mx);
		return (rv);
	}

	NNI_LIST_FOREACH (&s->s_options, sopt) {
		if (strcmp(sopt->name, name) == 0) {
			size_t sz = sopt->sz;
			if (sopt->sz > *szp) {
				sz = *szp;
			}
			*szp = sopt->sz;
			memcpy(val, sopt->data, sz);
			rv = 0;
			break;
		}
	}

	nni_mtx_unlock(&s->s_mx);
	return (rv);
}

uint32_t
nni_sock_flags(nni_sock *sock)
{
	return (sock->s_flags);
}
