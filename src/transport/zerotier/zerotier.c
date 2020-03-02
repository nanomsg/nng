//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/nng_impl.h"

#include "nng/transport/zerotier/zerotier.h"

#include <zerotiercore/ZeroTierOne.h>

// ZeroTier Transport.  This sits on the ZeroTier L2 network, which itself
// is implemented on top of UDP.  This requires the 3rd party
// libzerotiercore library (which is GPLv3!) and platform specific UDP
// functionality to be built in.  Note that care must be taken to link
// dynamically if one wishes to avoid making your entire application GPL3.
// (Alternatively ZeroTier offers commercial licenses which may prevent
// this particular problem.)  This implementation does not make use of
// certain advanced capabilities in ZeroTier such as more sophisticated
// route management and TCP fallback.  You need to have connectivity
// to the Internet to use this.  (Or at least to your Planetary root.)
//
// Because ZeroTier takes a while to establish connectivity, it is even
// more important that applications using the ZeroTier transport not
// assume that a connection will be immediately available.  It can take
// quite a few seconds for peer-to-peer connectivity to be established.
//
// The ZeroTier transport was funded by Capitar IT Group, BV.
//
// This transport is highly experimental.

// ZeroTier and UDP are connectionless, but nng is designed around
// connection oriented paradigms.  An "unreliable" connection is created
// on top using our own network protocol.  The details of this are
// documented in the RFC.

// Every participant has an "address", which is a 64-bit value constructed
// using the ZT node number in the upper 40-bits, and a 24-bit port number
// in the lower bits.  We elect to operate primarily on these addresses,
// but the wire protocol relies on just conveying the 24-bit port along
// with the MAC address (from which the ZT node number can be derived,
// given the network ID.)

typedef struct zt_pipe     zt_pipe;
typedef struct zt_ep       zt_ep;
typedef struct zt_node     zt_node;
typedef struct zt_frag     zt_frag;
typedef struct zt_fraglist zt_fraglist;

// Port numbers are stored as 24-bit values in network byte order.
#define ZT_GET24(ptr, v)                              \
	v = (((uint32_t)((uint8_t)(ptr)[0])) << 16) + \
	    (((uint32_t)((uint8_t)(ptr)[1])) << 8) +  \
	    (((uint32_t)(uint8_t)(ptr)[2]))

#define ZT_PUT24(ptr, u)                                     \
	do {                                                 \
		(ptr)[0] = (uint8_t)(((uint32_t)(u)) >> 16); \
		(ptr)[1] = (uint8_t)(((uint32_t)(u)) >> 8);  \
		(ptr)[2] = (uint8_t)((uint32_t)(u));         \
	} while (0)

static const uint16_t     zt_ethertype = 0x901;
static const uint8_t      zt_version   = 0x01;
static const uint32_t     zt_ephemeral = 0x800000u; // start of ephemeral ports
static const uint32_t     zt_max_port  = 0xffffffu; // largest port
static const uint32_t     zt_port_mask = 0xffffffu; // mask of valid ports
static const uint32_t     zt_port_shift = 24;
static const int          zt_conn_tries = 240;   // max connect attempts
static const nng_duration zt_conn_time  = 500;   // between attempts (msec)
static const int          zt_ping_tries = 10;    // max keepalive attempts
static const nng_duration zt_ping_time  = 60000; // keepalive time (msec)

// These are compile time tunables for now.
enum zt_tunables {
	zt_listenq       = 128,   // backlog queue length
	zt_listen_expire = 10000, // maximum time in backlog (msec)
	zt_rcv_bufsize   = 4096,  // max UDP recv
	zt_udp_sendq     = 16,    // outgoing UDP queue length
	zt_recvq         = 2,     // max pending recv (per pipe)
	zt_recv_stale    = 1000,  // frags older than are stale (msec)
};

enum zt_op_codes {
	zt_op_data     = 0x00, // data, final fragment
	zt_op_conn_req = 0x10, // connect request
	zt_op_conn_ack = 0x12, // connect accepted
	zt_op_disc_req = 0x20, // disconnect request (no ack)
	zt_op_ping     = 0x30, // ping request
	zt_op_pong     = 0x32, // ping response
	zt_op_error    = 0x40, // error response
};

enum zt_offsets {
	zt_offset_op          = 0x00,
	zt_offset_flags       = 0x01,
	zt_offset_version     = 0x02, // protocol version number (2 bytes)
	zt_offset_zero1       = 0x04, // reserved, must be zero (1 byte)
	zt_offset_dst_port    = 0x05, // destination port (3 bytes)
	zt_offset_zero2       = 0x08, // reserved, must be zero (1 byte)
	zt_offset_src_port    = 0x09, // source port number (3 bytes)
	zt_offset_creq_proto  = 0x0C, // SP protocol number (2 bytes)
	zt_offset_cack_proto  = 0x0C, // SP protocol number (2 bytes)
	zt_offset_err_code    = 0x0C, // error code (1 byte)
	zt_offset_err_msg     = 0x0D, // error message (string)
	zt_offset_data_id     = 0x0C, // message ID (2 bytes)
	zt_offset_data_fragsz = 0x0E, // fragment size
	zt_offset_data_frag   = 0x10, // fragment number, first is 1 (2 bytes)
	zt_offset_data_nfrag  = 0x12, // total fragments (2 bytes)
	zt_offset_data_data   = 0x14, // user payload
	zt_size_headers       = 0x0C, // size of headers
	zt_size_conn_req      = 0x0E, // size of conn_req (connect request)
	zt_size_conn_ack      = 0x0E, // size of conn_ack (connect reply)
	zt_size_disc_req      = 0x0C, // size of disc_req (disconnect)
	zt_size_ping          = 0x0C, // size of ping request
	zt_size_pong          = 0x0C, // size of ping reply
	zt_size_data          = 0x14, // size of data message (w/o payload)
};

enum zt_errors {
	zt_err_refused = 0x01, // Connection refused
	zt_err_notconn = 0x02, // Connection does not exit
	zt_err_wrongsp = 0x03, // SP protocol mismatch
	zt_err_proto   = 0x04, // Other protocol error
	zt_err_msgsize = 0x05, // Message to large
	zt_err_unknown = 0x06, // Other errors
};

// This node structure is wrapped around the ZT_node; this allows us to
// have multiple endpoints referencing the same ZT_node, but also to
// support different nodes (identities) based on different homedirs.
// This means we need to stick these on a global linked list, manage
// them with a reference count, and uniquely identify them using the
// homedir.
struct zt_node {
	char            zn_path[NNG_MAXADDRLEN]; // ought to be sufficient
	nni_file_lockh *zn_flock;
	ZT_Node *       zn_znode;
	uint64_t        zn_self;
	nni_list_node   zn_link;
	bool            zn_closed;
	nni_plat_udp *  zn_udp4;
	nni_plat_udp *  zn_udp6;
	nni_list        zn_eplist;
	nni_list        zn_plist;
	nni_idhash *    zn_ports;
	nni_idhash *    zn_eps;
	nni_idhash *    zn_lpipes;
	nni_idhash *    zn_rpipes;
	nni_aio *       zn_rcv4_aio;
	uint8_t *       zn_rcv4_buf;
	nng_sockaddr    zn_rcv4_addr;
	nni_aio *       zn_rcv6_aio;
	uint8_t *       zn_rcv6_buf;
	nng_sockaddr    zn_rcv6_addr;
	nni_thr         zn_bgthr;
	int64_t         zn_bgtime;
	nni_cv          zn_bgcv;
	nni_cv          zn_snd6_cv;
};

// The fragment list is used to keep track of incoming received
// fragments for reassembly into a complete message.
struct zt_fraglist {
	nni_time     fl_time;  // time first frag was received
	uint32_t     fl_msgid; // message id
	int          fl_ready; // we have all messages
	size_t       fl_fragsz;
	unsigned int fl_nfrags;
	uint8_t *    fl_missing;
	size_t       fl_missingsz;
	nni_msg *    fl_msg;
};

struct zt_pipe {
	nni_list_node   zp_link;
	zt_node *       zp_ztn;
	nni_pipe *      zp_npipe;
	uint64_t        zp_nwid;
	uint64_t        zp_laddr;
	uint64_t        zp_raddr;
	uint16_t        zp_peer;
	uint16_t        zp_proto;
	uint16_t        zp_next_msgid;
	size_t          zp_rcvmax;
	size_t          zp_mtu;
	nni_aio *       zp_user_rxaio;
	nni_time        zp_last_recv;
	zt_fraglist     zp_recvq[zt_recvq];
	int             zp_ping_try;
	int             zp_ping_tries;
	bool            zp_closed;
	nni_duration    zp_ping_time;
	nni_aio *       zp_ping_aio;
	uint8_t *       zp_send_buf;
	nni_atomic_flag zp_reaped;
	nni_reap_item   zp_reap;
};

typedef struct zt_creq zt_creq;
struct zt_creq {
	uint64_t cr_expire;
	uint64_t cr_raddr;
	uint16_t cr_proto;
};

struct zt_ep {
	nni_list_node ze_link;
	char          ze_home[NNG_MAXADDRLEN]; // should be enough
	zt_node *     ze_ztn;
	uint64_t      ze_nwid;
	bool          ze_running;
	uint64_t      ze_raddr; // remote node address
	uint64_t      ze_laddr; // local node address
	uint16_t      ze_proto;
	size_t        ze_rcvmax;
	nni_aio *     ze_aio;
	nni_aio *     ze_creq_aio;
	bool          ze_creq_active;
	int           ze_creq_try;
	nni_list      ze_aios;
	int           ze_mtu;
	int           ze_ping_tries;
	nni_duration  ze_ping_time;
	nni_duration  ze_conn_time;
	int           ze_conn_tries;

	// Incoming connection requests (server only).  We only
	// only have "accepted" requests -- that is we won't have an
	// established connection/pipe unless the application calls
	// accept.  Since the "application" is our library, that should
	// be pretty much as fast we can run.
	zt_creq       ze_creqs[zt_listenq];
	int           ze_creq_head;
	int           ze_creq_tail;
	nni_dialer *  ze_ndialer;
	nni_listener *ze_nlistener;
};

// Locking strategy.  At present the ZeroTier core is not reentrant or fully
// threadsafe.  (We expect this will be fixed.)  Furthermore, there are
// some significant challenges in dealing with locks associated with the
// callbacks, etc.  So we take a big-hammer approach, and just use a single
// global lock for everything.  We hold this lock when calling into the
// ZeroTier framework.  Since ZeroTier has no independent threads, that
// means that it will always hold this lock in its core, and the lock will
// also be held automatically in any of our callbacks.  We never hold any
// other locks across ZeroTier core calls. We may not acquire the global
// lock in callbacks (they will already have it held). Any other locks
// can be acquired as long as they are not held during calls into ZeroTier.
//
// This will have a detrimental impact on performance, but to be completely
// honest we don't think anyone will be using the ZeroTier transport in
// performance critical applications; scalability may become a factor for
// large servers sitting in a ZeroTier hub situation.  (Then again, since
// only the zerotier processing is single threaded, it may not
// be that much of a bottleneck -- really depends on how expensive these
// operations are.  We can use lockstat or other lock-hotness tools to
// check for this later.)

static nni_mtx  zt_lk;
static nni_list zt_nodes;

static void zt_ep_send_conn_req(zt_ep *);
static void zt_ep_conn_req_cb(void *);
static void zt_ep_doaccept(zt_ep *);
static void zt_pipe_dorecv(zt_pipe *);
static int  zt_pipe_alloc(zt_pipe **, zt_ep *, uint64_t, uint64_t, bool);
static void zt_pipe_ping_cb(void *);
static void zt_fraglist_clear(zt_fraglist *);
static void zt_fraglist_free(zt_fraglist *);
static void zt_virtual_recv(ZT_Node *, void *, void *, uint64_t, void **,
    uint64_t, uint64_t, unsigned int, unsigned int, const void *,
    unsigned int);
static void zt_pipe_start_ping(zt_pipe *);

static int64_t
zt_now(void)
{
	// We return msec
	return ((int64_t) nni_clock());
}

static void
zt_bgthr(void *arg)
{
	zt_node *ztn = arg;
	int64_t  now;

	nni_mtx_lock(&zt_lk);
	for (;;) {
		now = zt_now();

		if (ztn->zn_closed) {
			break;
		}

		if (now < ztn->zn_bgtime) {
			nni_cv_until(&ztn->zn_bgcv, (nni_time) ztn->zn_bgtime);
			continue;
		}

		ztn->zn_bgtime = 0;
		ZT_Node_processBackgroundTasks(ztn->zn_znode, NULL, now, &now);

		ztn->zn_bgtime = now;
	}
	nni_mtx_unlock(&zt_lk);
}

static void
zt_node_resched(zt_node *ztn, int64_t msec)
{
	if (msec > ztn->zn_bgtime && ztn->zn_bgtime != 0) {
		return;
	}
	ztn->zn_bgtime = msec;
	nni_cv_wake1(&ztn->zn_bgcv);
}

static void
zt_node_rcv4_cb(void *arg)
{
	zt_node *               ztn = arg;
	nni_aio *               aio = ztn->zn_rcv4_aio;
	struct sockaddr_storage sa;
	struct sockaddr_in *    sin;
	nng_sockaddr_in *       nsin;
	int64_t                 now;

	if (nni_aio_result(aio) != 0) {
		// Outside of memory exhaustion, we can't really think
		// of any reason for this to legitimately fail.
		// Arguably we should inject a fallback delay, but for
		// now we just carry on.
		return;
	}

	memset(&sa, 0, sizeof(sa));
	sin                  = (void *) &sa;
	nsin                 = &ztn->zn_rcv4_addr.s_in;
	sin->sin_family      = AF_INET;
	sin->sin_port        = nsin->sa_port;
	sin->sin_addr.s_addr = nsin->sa_addr;

	nni_mtx_lock(&zt_lk);
	now = zt_now();

	// We are not going to perform any validation of the data; we
	// just pass this straight into the ZeroTier core.
	// XXX: CHECK THIS, if it fails then we have a fatal error with
	// the znode, and have to shut everything down.
	ZT_Node_processWirePacket(ztn->zn_znode, NULL, now, 0, (void *) &sa,
	    ztn->zn_rcv4_buf, nni_aio_count(aio), &now);

	// Schedule background work
	zt_node_resched(ztn, now);

	// Schedule another receive.
	if (ztn->zn_udp4 != NULL) {
		nni_iov iov;
		iov.iov_buf = ztn->zn_rcv4_buf;
		iov.iov_len = zt_rcv_bufsize;
		nni_aio_set_iov(aio, 1, &iov);

		nni_aio_set_input(aio, 0, &ztn->zn_rcv4_addr);

		nni_plat_udp_recv(ztn->zn_udp4, aio);
	}
	nni_mtx_unlock(&zt_lk);
}

static void
zt_node_rcv6_cb(void *arg)
{
	zt_node *                ztn = arg;
	nni_aio *                aio = ztn->zn_rcv6_aio;
	struct sockaddr_storage  sa;
	struct sockaddr_in6 *    sin6;
	struct nng_sockaddr_in6 *nsin6;
	int64_t                  now;

	if (nni_aio_result(aio) != 0) {
		// Outside of memory exhaustion, we can't really think
		// of any reason for this to legitimately fail.
		// Arguably we should inject a fallback delay, but for
		// now we just carry on.
		return;
	}

	memset(&sa, 0, sizeof(sa));
	sin6              = (void *) &sa;
	nsin6             = &ztn->zn_rcv6_addr.s_in6;
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port   = nsin6->sa_port;
	memcpy(&sin6->sin6_addr, nsin6->sa_addr, 16);

	nni_mtx_lock(&zt_lk);
	now = (uint64_t) zt_now(); // msec

	// We are not going to perform any validation of the data; we
	// just pass this straight into the ZeroTier core.
	ZT_Node_processWirePacket(ztn->zn_znode, NULL, now, 0, (void *) &sa,
	    ztn->zn_rcv6_buf, nni_aio_count(aio), &now);

	// Schedule background work
	zt_node_resched(ztn, now);

	// Schedule another receive.
	if (ztn->zn_udp6 != NULL) {
		nni_iov iov;
		iov.iov_buf = ztn->zn_rcv6_buf;
		iov.iov_len = zt_rcv_bufsize;
		nni_aio_set_iov(aio, 1, &iov);
		nni_aio_set_input(aio, 0, &ztn->zn_rcv6_addr);
		nni_plat_udp_recv(ztn->zn_udp6, aio);
	}
	nni_mtx_unlock(&zt_lk);
}

static uint64_t
zt_mac_to_node(uint64_t mac, uint64_t nwid)
{
	uint64_t node;
	// This extracts a node address from a mac address.  The
	// network ID is mixed in, and has to be extricated.  We
	// the node ID is located in the lower 40 bits, and scrambled
	// against the nwid.
	node = mac & 0xffffffffffull;
	node ^= ((nwid >> 8) & 0xff) << 32;
	node ^= ((nwid >> 16) & 0xff) << 24;
	node ^= ((nwid >> 24) & 0xff) << 16;
	node ^= ((nwid >> 32) & 0xff) << 8;
	node ^= (nwid >> 40) & 0xff;
	return (node);
}

static uint64_t
zt_node_to_mac(uint64_t node, uint64_t nwid)
{
	uint64_t mac;
	// We use LSB of network ID, and make sure that we clear
	// multicast and set local administration -- this is the first
	// octet of the 48 bit mac address.  We also avoid 0x52, which
	// is known to be used in KVM, libvirt, etc.
	mac = ((uint8_t)(nwid & 0xfe) | 0x02);
	if (mac == 0x52) {
		mac = 0x32;
	}
	mac <<= 40;
	mac |= node;
	// The rest of the network ID is XOR'd in, in reverse byte
	// order.
	mac ^= ((nwid >> 8) & 0xff) << 32;
	mac ^= ((nwid >> 16) & 0xff) << 24;
	mac ^= ((nwid >> 24) & 0xff) << 16;
	mac ^= ((nwid >> 32) & 0xff) << 8;
	mac ^= (nwid >> 40) & 0xff;
	return (mac);
}

static int
zt_result(enum ZT_ResultCode rv)
{
	switch (rv) {
	case ZT_RESULT_OK:
		return (0);
	case ZT_RESULT_OK_IGNORED:
		return (0);
	case ZT_RESULT_FATAL_ERROR_OUT_OF_MEMORY:
		return (NNG_ENOMEM);
	case ZT_RESULT_FATAL_ERROR_DATA_STORE_FAILED:
		return (NNG_EPERM);
	case ZT_RESULT_FATAL_ERROR_INTERNAL:
		return (NNG_EINTERNAL);
	case ZT_RESULT_ERROR_NETWORK_NOT_FOUND:
		return (NNG_EADDRINVAL);
	case ZT_RESULT_ERROR_UNSUPPORTED_OPERATION:
		return (NNG_ENOTSUP);
	case ZT_RESULT_ERROR_BAD_PARAMETER:
		return (NNG_EINVAL);
	default:
		return (NNG_ETRANERR + (int) rv);
	}
}

// ZeroTier Node API callbacks
static int
zt_virtual_config(ZT_Node *node, void *userptr, void *thr, uint64_t nwid,
    void **netptr, enum ZT_VirtualNetworkConfigOperation op,
    const ZT_VirtualNetworkConfig *config)
{
	zt_node *ztn = userptr;
	zt_ep *  ep;

	NNI_ARG_UNUSED(thr);
	NNI_ARG_UNUSED(netptr);

	NNI_ASSERT(node == ztn->zn_znode);

	// Maybe we don't have to create taps or anything like that.
	// We do get our mac and MTUs from this, so there's that.
	switch (op) {
	case ZT_VIRTUAL_NETWORK_CONFIG_OPERATION_UP:
	case ZT_VIRTUAL_NETWORK_CONFIG_OPERATION_CONFIG_UPDATE:

		// We only really care about changes to the MTU.  From
		// an API perspective the MAC could change, but that
		// cannot really happen because the node identity and
		// the nwid are fixed.
		NNI_LIST_FOREACH (&ztn->zn_eplist, ep) {
			NNI_ASSERT(nwid == config->nwid);
			if (ep->ze_nwid != config->nwid) {
				continue;
			}
			ep->ze_mtu = config->mtu;
		}
		break;
	case ZT_VIRTUAL_NETWORK_CONFIG_OPERATION_DESTROY:
	case ZT_VIRTUAL_NETWORK_CONFIG_OPERATION_DOWN:
	// XXX: tear down endpoints?
	default:
		break;
	}
	return (0);
}

// zt_send modifies the start of the supplied buffer to update the
// message headers with protocol specific details (version, port numbers,
// etc.) and then sends it over the virtual network.
static void
zt_send(zt_node *ztn, uint64_t nwid, uint8_t op, uint64_t raddr,
    uint64_t laddr, uint8_t *data, size_t len)
{
	uint64_t srcmac = zt_node_to_mac(laddr >> 24, nwid);
	uint64_t dstmac = zt_node_to_mac(raddr >> 24, nwid);
	int64_t  now    = zt_now();

	NNI_ASSERT(len >= zt_size_headers);
	data[zt_offset_op]    = op;
	data[zt_offset_flags] = 0;
	data[zt_offset_zero1] = 0;
	data[zt_offset_zero2] = 0;
	NNI_PUT16(data + zt_offset_version, zt_version);
	ZT_PUT24(data + zt_offset_dst_port, raddr & zt_port_mask);
	ZT_PUT24(data + zt_offset_src_port, laddr & zt_port_mask);

	(void) ZT_Node_processVirtualNetworkFrame(ztn->zn_znode, NULL, now,
	    nwid, srcmac, dstmac, zt_ethertype, 0, data, len, &now);

	zt_node_resched(ztn, now);
}

static void
zt_send_err(zt_node *ztn, uint64_t nwid, uint64_t raddr, uint64_t laddr,
    uint8_t err, const char *msg)
{
	uint8_t data[128];

	NNI_ASSERT((strlen(msg) + zt_offset_err_msg) < sizeof(data));

	data[zt_offset_err_code] = err;
	nni_strlcpy((char *) data + zt_offset_err_msg, msg,
	    sizeof(data) - zt_offset_err_msg);

	zt_send(ztn, nwid, zt_op_error, raddr, laddr, data,
	    strlen(msg) + zt_offset_err_msg);
}

static void
zt_pipe_send_err(zt_pipe *p, uint8_t err, const char *msg)
{
	zt_send_err(p->zp_ztn, p->zp_nwid, p->zp_raddr, p->zp_laddr, err, msg);
}

static void
zt_pipe_send_disc_req(zt_pipe *p)
{
	uint8_t data[zt_size_disc_req];

	zt_send(p->zp_ztn, p->zp_nwid, zt_op_disc_req, p->zp_raddr,
	    p->zp_laddr, data, sizeof(data));
}

static void
zt_pipe_send_ping(zt_pipe *p)
{
	uint8_t data[zt_size_ping];

	zt_send(p->zp_ztn, p->zp_nwid, zt_op_ping, p->zp_raddr, p->zp_laddr,
	    data, sizeof(data));
}

static void
zt_pipe_send_pong(zt_pipe *p)
{
	uint8_t data[zt_size_ping];

	zt_send(p->zp_ztn, p->zp_nwid, zt_op_pong, p->zp_raddr, p->zp_laddr,
	    data, sizeof(data));
}

static void
zt_pipe_send_conn_ack(zt_pipe *p)
{
	uint8_t data[zt_size_conn_ack];

	NNI_PUT16(data + zt_offset_cack_proto, p->zp_proto);
	zt_send(p->zp_ztn, p->zp_nwid, zt_op_conn_ack, p->zp_raddr,
	    p->zp_laddr, data, sizeof(data));
}

static void
zt_ep_send_conn_req(zt_ep *ep)
{
	uint8_t data[zt_size_conn_req];

	NNI_PUT16(data + zt_offset_creq_proto, ep->ze_proto);
	zt_send(ep->ze_ztn, ep->ze_nwid, zt_op_conn_req, ep->ze_raddr,
	    ep->ze_laddr, data, sizeof(data));
}

static void
zt_ep_recv_conn_ack(zt_ep *ep, uint64_t raddr, const uint8_t *data, size_t len)
{
	zt_node *ztn = ep->ze_ztn;
	nni_aio *aio = ep->ze_creq_aio;
	zt_pipe *p;
	int      rv;

	if (ep->ze_ndialer == NULL) {
		zt_send_err(ztn, ep->ze_nwid, raddr, ep->ze_laddr,
		    zt_err_proto, "Inappropriate operation");
		return;
	}

	if (len != zt_size_conn_ack) {
		zt_send_err(ztn, ep->ze_nwid, raddr, ep->ze_laddr,
		    zt_err_proto, "Bad message length");
		return;
	}

	if (ep->ze_creq_try == 0) {
		return;
	}

	// Do we already have a matching pipe?  If so, we can discard
	// the operation.  This should not happen, since we normally,
	// deregister the endpoint when we create the pipe.
	if ((nni_idhash_find(ztn->zn_lpipes, ep->ze_laddr, (void **) &p)) ==
	    0) {
		return;
	}

	if ((rv = zt_pipe_alloc(&p, ep, raddr, ep->ze_laddr, false)) != 0) {
		// We couldn't create the pipe, just drop it.
		nni_aio_finish_error(aio, rv);
		return;
	}
	NNI_GET16(data + zt_offset_cack_proto, p->zp_peer);

	// Reset the address of the endpoint, so that the next call to
	// ep_connect will bind a new one -- we are using this one for the
	// pipe.
	nni_idhash_remove(ztn->zn_eps, ep->ze_laddr);
	ep->ze_laddr = 0;

	nni_aio_set_output(aio, 0, p);
	nni_aio_finish(aio, 0, 0);
}

static void
zt_ep_recv_conn_req(zt_ep *ep, uint64_t raddr, const uint8_t *data, size_t len)
{
	zt_node *ztn = ep->ze_ztn;
	zt_pipe *p;
	int      i;

	if (ep->ze_nlistener == NULL) {
		zt_send_err(ztn, ep->ze_nwid, raddr, ep->ze_laddr,
		    zt_err_proto, "Inappropriate operation");
		return;
	}
	if (len != zt_size_conn_req) {
		zt_send_err(ztn, ep->ze_nwid, raddr, ep->ze_laddr,
		    zt_err_proto, "Bad message length");
		return;
	}

	// If we already have created a pipe for this connection
	// then just reply the conn ack.
	if ((nni_idhash_find(ztn->zn_rpipes, raddr, (void **) &p)) == 0) {
		zt_pipe_send_conn_ack(p);
		return;
	}

	// We may already have a connection request queued (if this was
	// a resend for example); if that's the case we just ignore
	// this one.
	for (i = ep->ze_creq_tail; i != ep->ze_creq_head; i++) {
		if (ep->ze_creqs[i % zt_listenq].cr_raddr == raddr) {
			return;
		}
	}
	// We may already have filled our listenq, in which case we just drop.
	if ((ep->ze_creq_tail + zt_listenq) == ep->ze_creq_head) {
		// We have taken as many as we can, so just drop it.
		return;
	}

	// Record the connection request, and then process any
	// pending acceptors.
	i = ep->ze_creq_head % zt_listenq;

	NNI_GET16(data + zt_offset_creq_proto, ep->ze_creqs[i].cr_proto);
	ep->ze_creqs[i].cr_raddr  = raddr;
	ep->ze_creqs[i].cr_expire = nni_clock() + zt_listen_expire;
	ep->ze_creq_head++;

	zt_ep_doaccept(ep);
}

static void
zt_ep_recv_error(zt_ep *ep, const uint8_t *data, size_t len)
{
	int code;

	// Most of the time we don't care about errors.  The exception here
	// is that when we have an outstanding CON_REQ, we would like to
	// process that appropriately.

	if (ep->ze_ndialer == NULL) {
		// Not a dialer. Drop it.
		return;
	}

	if (len < zt_offset_err_msg) {
		// Malformed error frame.
		return;
	}

	code = data[zt_offset_err_code];
	switch (code) {
	case zt_err_refused:
		code = NNG_ECONNREFUSED;
		break;
	case zt_err_notconn:
		code = NNG_ECLOSED;
		break;
	case zt_err_wrongsp:
		code = NNG_EPROTO;
		break;
	default:
		code = NNG_ETRANERR;
		break;
	}

	if (ep->ze_creq_active) {
		ep->ze_creq_try    = 0;
		ep->ze_creq_active = 0;
		nni_aio_finish_error(ep->ze_creq_aio, code);
	}
}

static void
zt_ep_virtual_recv(
    zt_ep *ep, uint8_t op, uint64_t raddr, const uint8_t *data, size_t len)
{
	// Only listeners should be receiving.  Dialers receive on the pipe,
	// rather than the endpoint.  The only message that endpoints can
	// receive are connection requests.
	switch (op) {
	case zt_op_conn_req:
		zt_ep_recv_conn_req(ep, raddr, data, len);
		return;
	case zt_op_conn_ack:
		zt_ep_recv_conn_ack(ep, raddr, data, len);
		return;
	case zt_op_error:
		zt_ep_recv_error(ep, data, len);
		return;
	default:
		zt_send_err(ep->ze_ztn, ep->ze_nwid, raddr, ep->ze_laddr,
		    zt_err_proto, "Bad operation");
		return;
	}
}

static void
zt_pipe_close_err(zt_pipe *p, int err, uint8_t code, const char *msg)
{
	nni_aio *aio;
	if ((aio = p->zp_user_rxaio) != NULL) {
		p->zp_user_rxaio = NULL;
		nni_aio_finish_error(aio, err);
	}
	nni_aio_close(p->zp_ping_aio);
	p->zp_closed = true;
	if (msg != NULL) {
		zt_pipe_send_err(p, code, msg);
	}
}

static void
zt_pipe_recv_data(zt_pipe *p, const uint8_t *data, size_t len)
{
	uint16_t     msgid;
	uint16_t     fragno;
	uint16_t     nfrags;
	size_t       fragsz;
	zt_fraglist *fl;
	int          i;
	int          slot;
	uint8_t      bit;
	uint8_t *    body;

	if (len < zt_size_data) {
		// Runt frame.  Drop it and close pipe with a protocol error.
		zt_pipe_close_err(p, NNG_EPROTO, zt_err_proto, "Runt frame");
		return;
	}

	NNI_GET16(data + zt_offset_data_id, msgid);
	NNI_GET16(data + zt_offset_data_fragsz, fragsz);
	NNI_GET16(data + zt_offset_data_frag, fragno);
	NNI_GET16(data + zt_offset_data_nfrag, nfrags);
	len -= zt_offset_data_data;
	data += zt_offset_data_data;

	// Check for cases where message size is clearly too large.  Note
	// that we only can catch the case where a message is larger by
	// more than a fragment, since the final fragment may be shorter,
	// and we won't know that until we receive it.
	if ((p->zp_rcvmax > 0) &&
	    ((nfrags * fragsz) >= (p->zp_rcvmax + fragsz))) {
		// Discard, as the forwarder might be on the other side
		// of a device. This is gentler than just shutting the pipe
		// down.  Sending a remote error might be polite, but since
		// most peers will close the pipe on such an error, we
		// simply silently discard it.
		return;
	}

	// We run the recv logic once, to clear stale fragment entries.
	zt_pipe_dorecv(p);

	// Find a suitable fragment slot.
	slot = -1;
	for (i = 0; i < zt_recvq; i++) {
		fl = &p->zp_recvq[i];
		// This was our message ID, we always use it.
		if (msgid == fl->fl_msgid) {
			slot = i;
			break;
		}

		if (slot < 0) {
			slot = i;
		} else if (fl->fl_time < p->zp_recvq[slot].fl_time) {
			// This has an earlier expiration, so lets choose it.
			slot = i;
		}
	}

	NNI_ASSERT(slot >= 0);

	fl = &p->zp_recvq[slot];
	if (fl->fl_msgid != msgid) {
		// First fragment we've received for this message (but might
		// not be first fragment for message!)
		zt_fraglist_clear(fl);

		if (nni_msg_alloc(&fl->fl_msg, nfrags * fragsz) != 0) {
			// Out of memory.  We don't close the pipe, but
			// just fail to receive the message.  Bump a stat?
			return;
		}

		fl->fl_nfrags = nfrags;
		fl->fl_fragsz = fragsz;
		fl->fl_msgid  = msgid;
		fl->fl_time   = nni_clock();

		// Set the missing mask.
		memset(fl->fl_missing, 0xff, nfrags / 8);
		fl->fl_missing[nfrags / 8] |= ((1 << (nfrags % 8)) - 1);
	}
	if ((nfrags != fl->fl_nfrags) || (fragsz != fl->fl_fragsz) ||
	    (fragno >= nfrags) || (fragsz == 0) || (nfrags == 0) ||
	    ((fragno != (nfrags - 1)) && (len != fragsz))) {
		// Protocol error, message parameters changed.
		zt_pipe_close_err(
		    p, NNG_EPROTO, zt_err_proto, "Invalid message parameters");
		zt_fraglist_clear(fl);
		return;
	}

	bit = (uint8_t)(1 << (fragno % 8));
	if ((fl->fl_missing[fragno / 8] & bit) == 0) {
		// We've already got this fragment, ignore it.  We don't
		// bother to check for changed data.
		return;
	}

	fl->fl_missing[fragno / 8] &= ~(bit);
	body = nni_msg_body(fl->fl_msg);
	body += fragno * fragsz;
	memcpy(body, data, len);
	if (fragno == (nfrags - 1)) {
		// Last frag, maybe shorten the message.
		nni_msg_chop(fl->fl_msg, (fragsz - len));
		if ((nni_msg_len(fl->fl_msg) > p->zp_rcvmax) &&
		    (p->zp_rcvmax > 0)) {
			// Strict enforcement of max recv.
			zt_fraglist_clear(fl);
			// Just discard the message.
			return;
		}
	}

	for (i = 0; i < ((nfrags + 7) / 8); i++) {
		if (fl->fl_missing[i]) {
			return;
		}
	}

	// We got all fragments... try to send it up.
	fl->fl_ready = 1;
	zt_pipe_dorecv(p);
}

static void
zt_pipe_recv_ping(zt_pipe *p, const uint8_t *data, size_t len)
{
	NNI_ARG_UNUSED(data);

	if (len != zt_size_ping) {
		zt_pipe_send_err(p, zt_err_proto, "Incorrect ping size");
		return;
	}
	zt_pipe_send_pong(p);
}

static void
zt_pipe_recv_pong(zt_pipe *p, const uint8_t *data, size_t len)
{
	NNI_ARG_UNUSED(data);

	if (len != zt_size_pong) {
		zt_pipe_send_err(p, zt_err_proto, "Incorrect pong size");
	}
}

static void
zt_pipe_recv_disc_req(zt_pipe *p, const uint8_t *data, size_t len)
{
	nni_aio *aio;
	NNI_ARG_UNUSED(data);
	NNI_ARG_UNUSED(len);

	// NB: lock held already.
	// Don't bother to check the length, going to disconnect anyway.
	if ((aio = p->zp_user_rxaio) != NULL) {
		p->zp_user_rxaio = NULL;
		p->zp_closed     = true;
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
}

static void
zt_pipe_recv_error(zt_pipe *p, const uint8_t *data, size_t len)
{
	nni_aio *aio;
	NNI_ARG_UNUSED(data);
	NNI_ARG_UNUSED(len);

	// Perhaps we should log an error message, but at the end of
	// the day, the details are just not that interesting.
	if ((aio = p->zp_user_rxaio) != NULL) {
		p->zp_user_rxaio = NULL;
		p->zp_closed     = true;
		nni_aio_finish_error(aio, NNG_ETRANERR);
	}
}

// This function is called when we have determined that a frame has
// arrived for a pipe.  The remote and local addresses were both
// matched by the caller.
static void
zt_pipe_virtual_recv(zt_pipe *p, uint8_t op, const uint8_t *data, size_t len)
{
	// We got data, so update our recv time.
	p->zp_last_recv = nni_clock();
	p->zp_ping_try  = 0;

	switch (op) {
	case zt_op_data:
		zt_pipe_recv_data(p, data, len);
		return;
	case zt_op_disc_req:
		zt_pipe_recv_disc_req(p, data, len);
		return;
	case zt_op_ping:
		zt_pipe_recv_ping(p, data, len);
		return;
	case zt_op_pong:
		zt_pipe_recv_pong(p, data, len);
		return;
	case zt_op_error:
		zt_pipe_recv_error(p, data, len);
		return;
	case zt_op_conn_req:
		zt_pipe_send_conn_ack(p);
		return;
	}
}

// This function is called when a frame arrives on the
// *virtual* network.
static void
zt_virtual_recv(ZT_Node *node, void *userptr, void *thr, uint64_t nwid,
    void **netptr, uint64_t srcmac, uint64_t dstmac, unsigned int ethertype,
    unsigned int vlanid, const void *payload, unsigned int len)
{
	zt_node *      ztn = userptr;
	uint8_t        op;
	const uint8_t *data = payload;
	uint16_t       version;
	uint32_t       rport;
	uint32_t       lport;
	zt_ep *        ep;
	zt_pipe *      p;
	uint64_t       raddr;
	uint64_t       laddr;

	NNI_ARG_UNUSED(node);
	NNI_ARG_UNUSED(thr);
	NNI_ARG_UNUSED(netptr);

	if ((ethertype != zt_ethertype) || (len < zt_size_headers) ||
	    (data[zt_offset_flags] != 0) || (data[zt_offset_zero1] != 0) ||
	    (data[zt_offset_zero2] != 0)) {
		return;
	}
	NNI_GET16(data + zt_offset_version, version);
	if (version != zt_version) {
		return;
	}
	if (vlanid != 0) { // for now we only use vlan 0.
		return;
	}

	op = data[zt_offset_op];

	ZT_GET24(data + zt_offset_dst_port, lport);
	ZT_GET24(data + zt_offset_src_port, rport);

	raddr = zt_mac_to_node(srcmac, nwid);
	raddr <<= 24;
	raddr |= rport;

	laddr = zt_mac_to_node(dstmac, nwid);
	laddr <<= 24;
	laddr |= lport;

	// NB: We are holding the zt_lock.

	// Look up a pipe, but also we use this chance to check that
	// the source address matches what the pipe was established with.
	// If the pipe does not match then we nak it.  Note that pipes can
	// appear on the znode twice (loopback), so we have to be careful
	// to check the entire set of parameters, and to check for server
	// vs. client pipes separately.

	// If its a local address match on a client pipe, process it.
	if ((nni_idhash_find(ztn->zn_lpipes, laddr, (void *) &p) == 0) &&
	    (p->zp_nwid == nwid) && (p->zp_raddr == raddr)) {
		zt_pipe_virtual_recv(p, op, data, len);
		return;
	}

	// If its a remote address match on a server pipe, process it.
	if ((nni_idhash_find(ztn->zn_rpipes, raddr, (void *) &p) == 0) &&
	    (p->zp_nwid == nwid) && (p->zp_laddr == laddr)) {
		zt_pipe_virtual_recv(p, op, data, len);
		return;
	}

	// No pipe, so look for an endpoint.
	if ((nni_idhash_find(ztn->zn_eps, laddr, (void **) &ep) == 0) &&
	    (ep->ze_nwid == nwid)) {
		// direct this to an endpoint.
		zt_ep_virtual_recv(ep, op, raddr, data, len);
		return;
	}

	// We have a request for which we have no listener, and no
	// pipe. For some of these we send back a NAK, but for others
	// we just drop the frame.
	switch (op) {
	case zt_op_conn_req:
		// No listener.  Connection refused.
		zt_send_err(ztn, nwid, raddr, laddr, zt_err_refused,
		    "Connection refused");
		return;
	case zt_op_data:
	case zt_op_ping:
	case zt_op_conn_ack:
		zt_send_err(ztn, nwid, raddr, laddr, zt_err_notconn,
		    "Connection not found");
		break;
	case zt_op_error:
	case zt_op_pong:
	case zt_op_disc_req:
	default:
		// Just drop these.
		break;
	}
}

static void
zt_event_cb(ZT_Node *node, void *userptr, void *thr, enum ZT_Event event,
    const void *payload)
{
	NNI_ARG_UNUSED(node);
	NNI_ARG_UNUSED(userptr);
	NNI_ARG_UNUSED(thr);
	NNI_ARG_UNUSED(payload);

	switch (event) {
	case ZT_EVENT_ONLINE:  // Connected to the virtual net.
	case ZT_EVENT_UP:      // Node initialized (may not be connected).
	case ZT_EVENT_DOWN:    // Teardown of the node.
	case ZT_EVENT_OFFLINE: // Removal of the node from the net.
	case ZT_EVENT_TRACE:   // Local trace events.
		// printf("TRACE: %s\n", (const char *) payload);
		break;
	case ZT_EVENT_REMOTE_TRACE: // Remote trace, not supported.
	default:
		break;
	}
}

static const char *zt_files[] = {
	// clang-format off
	NULL, // none, i.e. not used at all
	"identity.public",
	"identity.secret",
	"planet",
	"moon.%llx",
	NULL, // peer, e.g. peers.d/<ID> -- we don't persist this
	"network.%llx",
	// clang-format on
};

static struct {
	size_t len;
	void * data;
} zt_ephemeral_state[ZT_STATE_OBJECT_NETWORK_CONFIG + 1];

static void
zt_state_put(ZT_Node *node, void *userptr, void *thr,
    enum ZT_StateObjectType objtype, const uint64_t objid[2], const void *data,
    int len)
{
	zt_node *ztn = userptr;
	char *   path;
	const char *template;
	char fname[32];

	NNI_ARG_UNUSED(node);
	NNI_ARG_UNUSED(thr);
	NNI_ARG_UNUSED(objid); // only use global files

	if ((objtype > ZT_STATE_OBJECT_NETWORK_CONFIG) ||
	    ((template = zt_files[(int) objtype]) == NULL)) {
		return;
	}

	(void) snprintf(fname, sizeof(fname), template,
	    (unsigned long long) objid[0], (unsigned long long) objid[1]);

	// If we have no valid path, then we just use ephemeral data.
	// Note that for moons, and so forth, we wind up just storing them
	// all in the same place, but it does not matter since we don't
	// really persist them anyway.
	if (strlen(ztn->zn_path) == 0) {
		void * ndata = NULL;
		void * odata = zt_ephemeral_state[objtype].data;
		size_t olen  = zt_ephemeral_state[objtype].len;
		if ((len >= 0) && ((ndata = nni_alloc(len)) != NULL)) {
			memcpy(ndata, data, len);
			zt_ephemeral_state[objtype].data = ndata;
			zt_ephemeral_state[objtype].len  = len;
		} else if (len < 0) {
			zt_ephemeral_state[objtype].data = NULL;
			zt_ephemeral_state[objtype].len  = 0;
		}

		if (olen > 0) {
			nni_free(odata, olen);
		}
		return;
	}

	if ((path = nni_file_join(ztn->zn_path, fname)) == NULL) {
		return;
	}

	if (len < 0) {
		(void) nni_file_delete(path);
	} else {
		(void) nni_file_put(path, data, len);
	}
	nni_strfree(path);
}

static int
zt_state_get(ZT_Node *node, void *userptr, void *thr,
    enum ZT_StateObjectType objtype, const uint64_t objid[2], void *data,
    unsigned int len)
{
	zt_node *ztn = userptr;
	char *   path;
	char     fname[32];
	const char *template;
	size_t sz;
	void * buf;

	NNI_ARG_UNUSED(node);
	NNI_ARG_UNUSED(thr);
	NNI_ARG_UNUSED(objid); // we only use global files

	if ((objtype > ZT_STATE_OBJECT_NETWORK_CONFIG) ||
	    ((template = zt_files[(int) objtype]) == NULL)) {
		return (-1);
	}
	snprintf(fname, sizeof(fname), template, objid[0], objid[1]);

	// If no base directory, we are using ephemeral data.
	if (strlen(ztn->zn_path) == 0) {
		if (zt_ephemeral_state[objtype].data == NULL) {
			return (-1);
		}
		if (zt_ephemeral_state[objtype].len > len) {
			return (-1);
		}
		len = zt_ephemeral_state[objtype].len;
		memcpy(data, zt_ephemeral_state[objtype].data, len);
		return (len);
	}

	if ((path = nni_file_join(ztn->zn_path, fname)) == NULL) {
		return (-1);
	}

	if (nni_file_get(path, &buf, &sz) != 0) {
		nni_strfree(path);
		return (-1);
	}
	nni_strfree(path);
	if (sz > len) {
		nni_free(buf, sz);
		return (-1);
	}
	memcpy(data, buf, sz);
	nni_free(buf, sz);
	return ((int) sz);
}

typedef struct zt_send_hdr {
	nni_sockaddr sa;
	size_t       len;
} zt_send_hdr;

// This function is called when ZeroTier desires to send a
// physical frame. The data is a UDP payload, the rest of the
// payload should be set over vanilla UDP.
static int
zt_wire_packet_send(ZT_Node *node, void *userptr, void *thr, int64_t socket,
    const struct sockaddr_storage *remaddr, const void *data, unsigned int len,
    unsigned int ttl)
{
	nni_aio *            aio;
	nni_sockaddr         addr;
	struct sockaddr_in * sin  = (void *) remaddr;
	struct sockaddr_in6 *sin6 = (void *) remaddr;
	zt_node *            ztn  = userptr;
	nni_plat_udp *       udp;
	uint8_t *            buf;
	zt_send_hdr *        hdr;
	nni_iov              iov;

	NNI_ARG_UNUSED(node);
	NNI_ARG_UNUSED(thr);
	NNI_ARG_UNUSED(socket);
	NNI_ARG_UNUSED(ttl);

	// Kind of unfortunate, but we have to convert the
	// sockaddr to a neutral form, and then back again in
	// the platform layer.
	switch (sin->sin_family) {
	case AF_INET:
		addr.s_in.sa_family = NNG_AF_INET;
		addr.s_in.sa_port   = sin->sin_port;
		addr.s_in.sa_addr   = sin->sin_addr.s_addr;
		udp                 = ztn->zn_udp4;
		break;
	case AF_INET6:
		addr.s_in6.sa_family = NNG_AF_INET6;
		addr.s_in6.sa_port   = sin6->sin6_port;
		udp                  = ztn->zn_udp6;
		memcpy(addr.s_in6.sa_addr, sin6->sin6_addr.s6_addr, 16);
		break;
	default:
		// No way to understand the address.
		return (-1);
	}

	if (nni_aio_alloc(&aio, NULL, NULL) != 0) {
		// Out of memory
		return (-1);
	}
	if ((buf = nni_alloc(sizeof(*hdr) + len)) == NULL) {
		nni_aio_free(aio);
		return (-1);
	}

	hdr = (void *) buf;
	buf += sizeof(*hdr);

	memcpy(buf, data, len);
	nni_aio_set_data(aio, 0, hdr);
	hdr->sa  = addr;
	hdr->len = len;
	nni_aio_set_input(aio, 0, &hdr->sa);

	iov.iov_buf = buf;
	iov.iov_len = len;
	nni_aio_set_iov(aio, 1, &iov);

	// This should be non-blocking/best-effort, so while
	// not great that we're holding the lock, also not tragic.
	nni_plat_udp_send(udp, aio);

	// UDP sending is "fast" on all platforms -- given that its
	// best effort only, this will complete immediately, resulting
	// in either a message on the wire, or a discarded frame.  We don't
	// care which.  (There may be a few thread context switches, but
	// none of them are going to have to wait for some unbounded time.)
	nni_aio_wait(aio);
	nni_aio_free(aio);
	nni_free(hdr, hdr->len + sizeof(*hdr));

	return (0);
}

static struct ZT_Node_Callbacks zt_callbacks = {
	.version                      = 0,
	.statePutFunction             = zt_state_put,
	.stateGetFunction             = zt_state_get,
	.wirePacketSendFunction       = zt_wire_packet_send,
	.virtualNetworkFrameFunction  = zt_virtual_recv,
	.virtualNetworkConfigFunction = zt_virtual_config,
	.eventCallback                = zt_event_cb,
	.pathCheckFunction            = NULL,
	.pathLookupFunction           = NULL,
};

static void
zt_node_destroy(zt_node *ztn)
{
	nni_aio_stop(ztn->zn_rcv4_aio);
	nni_aio_stop(ztn->zn_rcv6_aio);

	// Wait for background thread to exit!
	nni_thr_fini(&ztn->zn_bgthr);

	if (ztn->zn_znode != NULL) {
		ZT_Node_delete(ztn->zn_znode);
	}

	if (ztn->zn_udp4 != NULL) {
		nni_plat_udp_close(ztn->zn_udp4);
	}
	if (ztn->zn_udp6 != NULL) {
		nni_plat_udp_close(ztn->zn_udp6);
	}

	if (ztn->zn_rcv4_buf != NULL) {
		nni_free(ztn->zn_rcv4_buf, zt_rcv_bufsize);
	}
	if (ztn->zn_rcv6_buf != NULL) {
		nni_free(ztn->zn_rcv6_buf, zt_rcv_bufsize);
	}
	if (ztn->zn_flock != NULL) {
		nni_file_unlock(ztn->zn_flock);
	}
	nni_aio_free(ztn->zn_rcv4_aio);
	nni_aio_free(ztn->zn_rcv6_aio);
	nni_idhash_fini(ztn->zn_eps);
	nni_idhash_fini(ztn->zn_lpipes);
	nni_idhash_fini(ztn->zn_rpipes);
	nni_cv_fini(&ztn->zn_bgcv);
	NNI_FREE_STRUCT(ztn);
}

static int
zt_node_create(zt_node **ztnp, const char *path)
{
	zt_node *          ztn;
	nng_sockaddr       sa4;
	nng_sockaddr       sa6;
	int                rv;
	enum ZT_ResultCode zrv;
	nni_iov            iov;

	// XXX: Right now we depend on having both IPv6 and IPv4 available.
	// Probably we should support coping with the lack of either of them.

	// We want to bind to any address we can (for now).
	memset(&sa4, 0, sizeof(sa4));
	sa4.s_in.sa_family = NNG_AF_INET;
	memset(&sa6, 0, sizeof(sa6));
	sa6.s_in6.sa_family = NNG_AF_INET6;

	if ((ztn = NNI_ALLOC_STRUCT(ztn)) == NULL) {
		return (NNG_ENOMEM);
	}
	NNI_LIST_INIT(&ztn->zn_eplist, zt_ep, ze_link);
	NNI_LIST_INIT(&ztn->zn_plist, zt_pipe, zp_link);
	nni_cv_init(&ztn->zn_bgcv, &zt_lk);
	nni_aio_alloc(&ztn->zn_rcv4_aio, zt_node_rcv4_cb, ztn);
	nni_aio_alloc(&ztn->zn_rcv6_aio, zt_node_rcv6_cb, ztn);

	if (((ztn->zn_rcv4_buf = nni_alloc(zt_rcv_bufsize)) == NULL) ||
	    ((ztn->zn_rcv6_buf = nni_alloc(zt_rcv_bufsize)) == NULL)) {
		zt_node_destroy(ztn);
		return (NNG_ENOMEM);
	}
	if (((rv = nni_idhash_init(&ztn->zn_ports)) != 0) ||
	    ((rv = nni_idhash_init(&ztn->zn_eps)) != 0) ||
	    ((rv = nni_idhash_init(&ztn->zn_lpipes)) != 0) ||
	    ((rv = nni_idhash_init(&ztn->zn_rpipes)) != 0) ||
	    ((rv = nni_thr_init(&ztn->zn_bgthr, zt_bgthr, ztn)) != 0) ||
	    ((rv = nni_plat_udp_open(&ztn->zn_udp4, &sa4)) != 0) ||
	    ((rv = nni_plat_udp_open(&ztn->zn_udp6, &sa6)) != 0)) {
		zt_node_destroy(ztn);
		return (rv);
	}

	if (strlen(path) > 0) {
		char *lkfile;
		if ((lkfile = nni_file_join(path, "lock")) == NULL) {
			zt_node_destroy(ztn);
			return (NNG_ENOMEM);
		}

		if ((rv = nni_file_lock(lkfile, &ztn->zn_flock)) != 0) {
			zt_node_destroy(ztn);
			nni_strfree(lkfile);
			return (rv);
		}
		nni_strfree(lkfile);
	}

	// Setup for dynamic ephemeral port allocations.  We
	// set the range to allow for ephemeral ports, but not
	// higher than the max port, and starting with an
	// initial random value.  Note that this should give us
	// about 8 million possible ephemeral ports.
	nni_idhash_set_limits(ztn->zn_ports, zt_ephemeral, zt_max_port,
	    (nni_random() % (zt_max_port - zt_ephemeral)) + zt_ephemeral);

	nni_strlcpy(ztn->zn_path, path, sizeof(ztn->zn_path));
	zrv = ZT_Node_new(&ztn->zn_znode, ztn, NULL, &zt_callbacks, zt_now());
	if (zrv != ZT_RESULT_OK) {
		zt_node_destroy(ztn);
		return (zt_result(zrv));
	}

	nni_list_append(&zt_nodes, ztn);

	ztn->zn_self = ZT_Node_address(ztn->zn_znode);

	nni_thr_run(&ztn->zn_bgthr);

	// Schedule an initial background run.
	zt_node_resched(ztn, 1);

	// Schedule receive
	iov.iov_buf = ztn->zn_rcv4_buf;
	iov.iov_len = zt_rcv_bufsize;
	nni_aio_set_iov(ztn->zn_rcv4_aio, 1, &iov);
	nni_aio_set_input(ztn->zn_rcv4_aio, 0, &ztn->zn_rcv4_addr);
	iov.iov_buf = ztn->zn_rcv6_buf;
	iov.iov_len = zt_rcv_bufsize;
	nni_aio_set_iov(ztn->zn_rcv6_aio, 1, &iov);
	nni_aio_set_input(ztn->zn_rcv6_aio, 0, &ztn->zn_rcv6_addr);

	nni_plat_udp_recv(ztn->zn_udp4, ztn->zn_rcv4_aio);
	nni_plat_udp_recv(ztn->zn_udp6, ztn->zn_rcv6_aio);

	*ztnp = ztn;
	return (0);
}

static int
zt_walk_moons(const char *path, void *arg)
{
	zt_node *   ztn = arg;
	const char *bn  = nni_file_basename(path);
	uint64_t    moonid;

	if (strncmp(bn, "moon.", 5) != 0) {
		return (NNI_FILE_WALK_CONTINUE);
	}
	if (nni_strtox64(bn + 5, &moonid) == 0) {
		ZT_Node_orbit(ztn->zn_znode, NULL, moonid, 0);
	}
	return (NNI_FILE_WALK_CONTINUE);
}

static int
zt_node_find(zt_ep *ep)
{
	zt_node *                ztn;
	int                      rv;
	ZT_VirtualNetworkConfig *cf;

	NNI_LIST_FOREACH (&zt_nodes, ztn) {
		if (strcmp(ep->ze_home, ztn->zn_path) == 0) {
			goto done;
		}
	}

	// We didn't find a node, so make one.  And try to
	// initialize it.
	if ((rv = zt_node_create(&ztn, ep->ze_home)) != 0) {
		return (rv);
	}

	// Load moons
	if (strlen(ep->ze_home) != 0) {
		(void) nni_file_walk(ep->ze_home, zt_walk_moons, ztn,
		    NNI_FILE_WALK_FILES_ONLY | NNI_FILE_WALK_SHALLOW);
	}

done:

	ep->ze_ztn = ztn;
	if (nni_list_node_active(&ep->ze_link)) {
		nni_list_node_remove(&ep->ze_link);
	}
	nni_list_append(&ztn->zn_eplist, ep);

	(void) ZT_Node_join(ztn->zn_znode, ep->ze_nwid, ztn, NULL);

	if ((cf = ZT_Node_networkConfig(ztn->zn_znode, ep->ze_nwid)) != NULL) {
		NNI_ASSERT(cf->nwid == ep->ze_nwid);
		ep->ze_mtu = cf->mtu;
		ZT_Node_freeQueryResult(ztn->zn_znode, cf);
	}

	return (0);
}

static int
zt_tran_init(void)
{
	nni_mtx_init(&zt_lk);
	NNI_LIST_INIT(&zt_nodes, zt_node, zn_link);
	return (0);
}

static void
zt_tran_fini(void)
{
	zt_node *ztn;

	nni_mtx_lock(&zt_lk);
	while ((ztn = nni_list_first(&zt_nodes)) != 0) {
		nni_list_remove(&zt_nodes, ztn);
		ztn->zn_closed = true;
		nni_cv_wake(&ztn->zn_bgcv);
		nni_mtx_unlock(&zt_lk);

		zt_node_destroy(ztn);

		nni_mtx_lock(&zt_lk);
	}
	nni_mtx_unlock(&zt_lk);

	for (int i = 0; i <= ZT_STATE_OBJECT_NETWORK_CONFIG; i++) {
		if (zt_ephemeral_state[i].len > 0) {
			nni_free(zt_ephemeral_state[i].data,
			    zt_ephemeral_state[i].len);
		}
	}
	NNI_ASSERT(nni_list_empty(&zt_nodes));
	nni_mtx_fini(&zt_lk);
}

static void
zt_pipe_close(void *arg)
{
	zt_pipe *p = arg;
	nni_aio *aio;

	nni_mtx_lock(&zt_lk);
	p->zp_closed = true;
	nni_aio_close(p->zp_ping_aio);
	if ((aio = p->zp_user_rxaio) != NULL) {
		p->zp_user_rxaio = NULL;
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
	zt_pipe_send_disc_req(p);
	nni_mtx_unlock(&zt_lk);
}

static int
zt_pipe_init(void *arg, nni_pipe *npipe)
{
	zt_pipe *p  = arg;
	p->zp_npipe = npipe;
	return (0);
}

static void
zt_pipe_fini(void *arg)
{
	zt_pipe *p   = arg;
	zt_node *ztn = p->zp_ztn;

	nni_aio_free(p->zp_ping_aio);

	// This tosses the connection details and all state.
	nni_mtx_lock(&zt_lk);
	nni_idhash_remove(ztn->zn_ports, p->zp_laddr & zt_port_mask);
	nni_idhash_remove(ztn->zn_lpipes, p->zp_laddr);
	nni_idhash_remove(ztn->zn_rpipes, p->zp_raddr);
	nni_mtx_unlock(&zt_lk);

	for (int i = 0; i < zt_recvq; i++) {
		zt_fraglist_free(&p->zp_recvq[i]);
	}
	nni_free(p->zp_send_buf, ZT_MAX_MTU);
	NNI_FREE_STRUCT(p);
}

static void
zt_pipe_reap(zt_pipe *p)
{
	if (!nni_atomic_flag_test_and_set(&p->zp_reaped)) {
		nni_reap(&p->zp_reap, zt_pipe_fini, p);
	}
}

static int
zt_pipe_alloc(
    zt_pipe **pipep, zt_ep *ep, uint64_t raddr, uint64_t laddr, bool listener)
{
	zt_pipe *p;
	int      rv;
	zt_node *ztn = ep->ze_ztn;
	int      i;
	size_t   maxfrag;
	size_t   maxfrags = 0;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((p->zp_send_buf = nni_alloc(ZT_MAX_MTU)) == NULL) {
		NNI_FREE_STRUCT(p);
		return (NNG_ENOMEM);
	}
	p->zp_ztn        = ztn;
	p->zp_raddr      = raddr;
	p->zp_laddr      = laddr;
	p->zp_proto      = ep->ze_proto;
	p->zp_nwid       = ep->ze_nwid;
	p->zp_mtu        = ep->ze_mtu;
	p->zp_rcvmax     = ep->ze_rcvmax;
	p->zp_ping_tries = ep->ze_ping_tries;
	p->zp_ping_time  = ep->ze_ping_time;
	p->zp_next_msgid = (uint16_t) nni_random();
	p->zp_ping_try   = 0;
	nni_atomic_flag_reset(&p->zp_reaped);

	if (listener) {
		// listener
		rv = nni_idhash_insert(ztn->zn_rpipes, raddr, p);
	} else {
		// dialer
		rv = nni_idhash_insert(ztn->zn_lpipes, laddr, p);
	}
	if ((rv != 0) ||
	    ((rv = nni_aio_alloc(&p->zp_ping_aio, zt_pipe_ping_cb, p)) != 0)) {
		zt_pipe_reap(p);
		return (rv);
	}

	// The largest fragment we can accept on this pipe. The MTU is
	// configurable by the network administrator.  Probably ZT would
	// pass a larger one (up to MAXMTU), but we honor the network
	// administration's configuration.
	maxfrag = p->zp_mtu - zt_offset_data_data;

	// The largest fragment count we can accept on this pipe.
	// This is rounded up to account for alignment.
	if (p->zp_rcvmax > 0) {
		maxfrags = (p->zp_rcvmax + (maxfrag - 1)) / maxfrag;
	}

	if ((maxfrags > 0xffff) || (maxfrags == 0)) {
		maxfrags = 0xffff;
	}

	for (i = 0; i < zt_recvq; i++) {
		zt_fraglist *fl  = &p->zp_recvq[i];
		fl->fl_time      = NNI_TIME_ZERO;
		fl->fl_msgid     = 0;
		fl->fl_ready     = 0;
		fl->fl_missingsz = (maxfrags + 7) / 8;
		fl->fl_missing   = nni_alloc(fl->fl_missingsz);
		if (fl->fl_missing == NULL) {
			zt_pipe_reap(p);
			return (NNG_ENOMEM);
		}
	}

	*pipep = p;
	return (0);
}

static void
zt_pipe_send(void *arg, nni_aio *aio)
{
	// As we are sending UDP, and there is no callback to worry
	// about, we just go ahead and send out a stream of messages
	// synchronously.
	zt_pipe *p    = arg;
	uint8_t *data = p->zp_send_buf;
	size_t   offset;
	uint16_t id;
	uint16_t nfrags;
	uint16_t fragno;
	size_t   fragsz;
	size_t   bytes;
	nni_msg *m;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	if ((m = nni_aio_get_msg(aio)) == NULL) {
		nni_aio_finish_error(aio, NNG_EINVAL);
		return;
	}

	nni_mtx_lock(&zt_lk);

	if (p->zp_closed) {
		nni_mtx_unlock(&zt_lk);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}

	fragsz = p->zp_mtu - zt_offset_data_data;
	NNI_ASSERT(fragsz < 0x10000); // Because zp_mtu is 16 bits

	bytes = nni_msg_header_len(m) + nni_msg_len(m);
	if (bytes >= (0xfffe * fragsz)) {
		nni_aio_finish_error(aio, NNG_EMSGSIZE);
		nni_mtx_unlock(&zt_lk);
		return;
	}
	// above check means nfrags will fit in 16-bits.
	nfrags = (uint16_t)((bytes + (fragsz - 1)) / fragsz);

	// get the next message ID, but skip 0
	if ((id = p->zp_next_msgid++) == 0) {
		id = p->zp_next_msgid++;
	}

	offset = 0;
	fragno = 0;
	do {
		uint8_t *dest    = data + zt_offset_data_data;
		size_t   room    = fragsz;
		size_t   fraglen = 0;
		size_t   len;

		// Prepend the header first.
		if ((len = nni_msg_header_len(m)) > 0) {
			if (len > fragsz) {
				// This shouldn't happen!  SP headers are
				// supposed to be quite small.
				nni_aio_finish_error(aio, NNG_EMSGSIZE);
				nni_mtx_unlock(&zt_lk);
				return;
			}
			memcpy(dest, nni_msg_header(m), len);
			dest += len;
			room -= len;
			offset += len;
			fraglen += len;
			nni_msg_header_clear(m);
		}

		len = nni_msg_len(m);
		if (len > room) {
			len = room;
		}
		memcpy(dest, nni_msg_body(m), len);

		nng_msg_trim(m, len);
		NNI_PUT16(data + zt_offset_data_id, id);
		NNI_PUT16(data + zt_offset_data_fragsz, (uint16_t) fragsz);
		NNI_PUT16(data + zt_offset_data_frag, fragno);
		NNI_PUT16(data + zt_offset_data_nfrag, nfrags);
		offset += len;
		fraglen += len;
		fragno++;
		zt_send(p->zp_ztn, p->zp_nwid, zt_op_data, p->zp_raddr,
		    p->zp_laddr, data, fraglen + zt_offset_data_data);
	} while (nni_msg_len(m) != 0);
	nni_mtx_unlock(&zt_lk);

	// NB, We never bothered to call nn_aio_sched, because we run this
	// synchronously, relying on UDP to simply discard messages if we
	// cannot deliver them.  This means that pipe send operations with
	// this transport are not cancellable.

	nni_aio_set_msg(aio, NULL);
	nni_msg_free(m);
	nni_aio_finish(aio, 0, offset);
}

static void
zt_pipe_cancel_recv(nni_aio *aio, void *arg, int rv)
{
	zt_pipe *p = arg;
	nni_mtx_lock(&zt_lk);
	if (p->zp_user_rxaio == aio) {
		p->zp_user_rxaio = NULL;
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&zt_lk);
}

static void
zt_fraglist_clear(zt_fraglist *fl)
{
	nni_msg *msg;

	fl->fl_ready = 0;
	fl->fl_msgid = 0;
	fl->fl_time  = NNI_TIME_ZERO;
	if ((msg = fl->fl_msg) != NULL) {
		fl->fl_msg = NULL;
		nni_msg_free(msg);
	}
	memset(fl->fl_missing, 0, fl->fl_missingsz);
}

static void
zt_fraglist_free(zt_fraglist *fl)
{
	zt_fraglist_clear(fl);
	nni_free(fl->fl_missing, fl->fl_missingsz);
	fl->fl_missing = NULL;
}

static void
zt_pipe_dorecv(zt_pipe *p)
{
	nni_aio *aio = p->zp_user_rxaio;
	nni_time now = nni_clock();

	if (aio == NULL) {
		return;
	}

	for (int i = 0; i < zt_recvq; i++) {
		zt_fraglist *fl = &p->zp_recvq[i];
		nni_msg *    msg;

		if (now > (fl->fl_time + zt_recv_stale)) {
			// fragment list is stale, clean it.
			zt_fraglist_clear(fl);
			continue;
		}
		if (!fl->fl_ready) {
			continue;
		}

		// Got data.  Let's pass it up.
		msg        = fl->fl_msg;
		fl->fl_msg = NULL;
		NNI_ASSERT(msg != NULL);

		p->zp_user_rxaio = NULL;
		nni_aio_finish_msg(aio, msg);
		zt_fraglist_clear(fl);
		return;
	}
}

static void
zt_pipe_recv(void *arg, nni_aio *aio)
{
	zt_pipe *p = arg;
	int      rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&zt_lk);
	if (p->zp_closed) {
		nni_mtx_unlock(&zt_lk);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if ((rv = nni_aio_schedule(aio, zt_pipe_cancel_recv, p)) != 0) {
		nni_mtx_unlock(&zt_lk);
		nni_aio_finish_error(aio, rv);
		return;
	}
	p->zp_user_rxaio = aio;
	zt_pipe_dorecv(p);
	nni_mtx_unlock(&zt_lk);
}

static uint16_t
zt_pipe_peer(void *arg)
{
	zt_pipe *pipe = arg;

	return (pipe->zp_peer);
}

static int
zt_get_nw_status(zt_node *ztn, uint64_t nwid, int *statusp)
{
	ZT_VirtualNetworkConfig *vcfg;
	int                      status;

	vcfg = ZT_Node_networkConfig(ztn->zn_znode, nwid);
	if (vcfg == NULL) {
		return (NNG_ECLOSED);
	}
	switch (vcfg->status) {
	case ZT_NETWORK_STATUS_REQUESTING_CONFIGURATION:
		status = NNG_ZT_STATUS_CONFIG;
		break;
	case ZT_NETWORK_STATUS_OK:
		status = NNG_ZT_STATUS_UP;
		break;
	case ZT_NETWORK_STATUS_ACCESS_DENIED:
		status = NNG_ZT_STATUS_DENIED;
		break;
	case ZT_NETWORK_STATUS_NOT_FOUND:
		status = NNG_ZT_STATUS_NOTFOUND;
		break;
	case ZT_NETWORK_STATUS_PORT_ERROR:
		status = NNG_ZT_STATUS_ERROR;
		break;
	case ZT_NETWORK_STATUS_CLIENT_TOO_OLD:
		status = NNG_ZT_STATUS_OBSOLETE;
		break;
	default:
		status = NNG_ZT_STATUS_UNKNOWN;
		break;
	}
	ZT_Node_freeQueryResult(ztn->zn_znode, vcfg);

	*statusp = status;
	return (0);
}

static int
zt_get_nw_name(zt_node *ztn, uint64_t nwid, void *buf, size_t *szp, nni_type t)
{
	ZT_VirtualNetworkConfig *vcfg;
	int                      rv;

	vcfg = ZT_Node_networkConfig(ztn->zn_znode, nwid);
	if (vcfg == NULL) {
		return (NNG_ECLOSED);
	}

	rv = nni_copyout_str(vcfg->name, buf, szp, t);
	ZT_Node_freeQueryResult(ztn->zn_znode, vcfg);

	return (rv);
}

static int
zt_pipe_get_recvmaxsz(void *arg, void *buf, size_t *szp, nni_type t)
{
	zt_pipe *p = arg;
	return (nni_copyout_size(p->zp_rcvmax, buf, szp, t));
}

static int
zt_pipe_get_nwid(void *arg, void *buf, size_t *szp, nni_type t)
{
	zt_pipe *p = arg;
	return (nni_copyout_u64(p->zp_nwid, buf, szp, t));
}

static int
zt_pipe_get_node(void *arg, void *buf, size_t *szp, nni_type t)
{
	zt_pipe *p = arg;
	return (nni_copyout_u64(p->zp_laddr >> 24, buf, szp, t));
}

static void
zt_pipe_ping_cb(void *arg)
{
	zt_pipe *p   = arg;
	nni_aio *aio = p->zp_ping_aio;
	int      rv;

	if ((rv = nni_aio_result(aio)) != 0) {
		// We were canceled.  That means we're done.
		return;
	}
	nni_mtx_lock(&zt_lk);
	if (p->zp_closed || aio == NULL || (p->zp_ping_tries == 0) ||
	    (p->zp_ping_time == NNG_DURATION_INFINITE) ||
	    (p->zp_ping_time == NNG_DURATION_ZERO)) {
		nni_mtx_unlock(&zt_lk);
		return;
	}
	if (p->zp_ping_try > p->zp_ping_tries) {
		// Ping count exceeded; the other side is AFK.
		// Close the pipe, but no need to send a reason to the peer.
		zt_pipe_close_err(p, NNG_ECLOSED, 0, NULL);
		nni_mtx_unlock(&zt_lk);
		return;
	}

	if (nni_clock() > (p->zp_last_recv + p->zp_ping_time)) {
		p->zp_ping_try++;
		zt_pipe_send_ping(p);
	}

	nni_sleep_aio(p->zp_ping_time, aio); // Schedule a recheck.
	nni_mtx_unlock(&zt_lk);
}

static void
zt_pipe_start_ping(zt_pipe *p)
{
	// send a gratuitous ping, and start the ping interval timer.
	if ((p->zp_ping_tries > 0) && (p->zp_ping_time != NNG_DURATION_ZERO) &&
	    (p->zp_ping_time != NNG_DURATION_INFINITE)) {
		p->zp_ping_try = 0;
		zt_pipe_send_ping(p);
		nni_sleep_aio(p->zp_ping_time, p->zp_ping_aio);
	}
}

static void
zt_ep_fini(void *arg)
{
	zt_ep *ep = arg;
	nni_aio_stop(ep->ze_creq_aio);
	nni_aio_free(ep->ze_creq_aio);
	NNI_FREE_STRUCT(ep);
}

static int
zt_parsehex(const char **sp, uint64_t *valp, bool wildok)
{
	int         n;
	const char *s = *sp;
	char        c;
	uint64_t    v;

	if (wildok && *s == '*') {
		*valp = 0;
		s++;
		*sp = s;
		return (0);
	}

	for (v = 0, n = 0; (n < 16) && isxdigit(c = tolower(*s)); n++, s++) {
		v *= 16;
		if (isdigit(c)) {
			v += (c - '0');
		} else {
			v += ((c - 'a') + 10);
		}
	}

	*sp   = s;
	*valp = v;
	return (n ? 0 : NNG_EINVAL);
}

static int
zt_parsedec(const char **sp, uint64_t *valp)
{
	int         n;
	const char *s = *sp;
	char        c;
	uint64_t    v;

	for (v = 0, n = 0; (n < 20) && isdigit(c = *s); n++, s++) {
		v *= 10;
		v += (c - '0');
	}
	*sp   = s;
	*valp = v;
	return (n ? 0 : NNG_EINVAL);
}

static int
zt_ep_init(void **epp, nni_url *url, nni_sock *sock, nni_dialer *ndialer,
    nni_listener *nlistener)
{
	zt_ep *     ep;
	uint64_t    node;
	uint64_t    port;
	int         rv;
	const char *h;

	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}

	ep->ze_mtu        = ZT_MIN_MTU;
	ep->ze_aio        = NULL;
	ep->ze_ping_tries = zt_ping_tries;
	ep->ze_ping_time  = zt_ping_time;
	ep->ze_conn_time  = zt_conn_time;
	ep->ze_conn_tries = zt_conn_tries;
	ep->ze_proto      = nni_sock_proto_id(sock);
	ep->ze_ndialer    = ndialer;
	ep->ze_nlistener  = nlistener;

	nni_aio_list_init(&ep->ze_aios);

	rv = nni_aio_alloc(&ep->ze_creq_aio, zt_ep_conn_req_cb, ep);
	if (rv != 0) {
		zt_ep_fini(ep);
		return (rv);
	}

	// Our URL format is:
	//
	// zt://<nodeid>.<nwid>:<port>
	//
	// The port must be specified, but may be zero.  The nodeid
	// may be '*' to refer to ourself.  There may be a trailing slash
	// which will be ignored.

	h = url->u_hostname;
	if (((strlen(url->u_path) == 1) && (url->u_path[0] != '/')) ||
	    (strlen(url->u_path) > 1) || (url->u_fragment != NULL) ||
	    (url->u_query != NULL) || (url->u_userinfo != NULL) ||
	    (zt_parsehex(&h, &node, true) != 0) || (*h++ != '.') ||
	    (zt_parsehex(&h, &ep->ze_nwid, false) != 0) ||
	    (node > 0xffffffffffull)) {
		return (NNG_EADDRINVAL);
	}
	h = url->u_port;
	if ((zt_parsedec(&h, &port) != 0) || (port > zt_max_port)) {
		return (NNG_EADDRINVAL);
	}

	// Parse the URL.
	if (nlistener != NULL) {
		// listener
		ep->ze_laddr = node;
		ep->ze_laddr <<= 24;
		ep->ze_laddr |= port;
		ep->ze_raddr     = 0;
		ep->ze_nlistener = nlistener;
	} else {
		// dialer
		if (port == 0) {
			return (NNG_EADDRINVAL);
		}
		ep->ze_raddr = node;
		ep->ze_raddr <<= 24;
		ep->ze_raddr |= port;
		ep->ze_laddr   = 0;
		ep->ze_ndialer = ndialer;
	}

	*epp = ep;
	return (0);
}

static int
zt_dialer_init(void **epp, nni_url *url, nni_dialer *d)
{
	return (zt_ep_init(epp, url, nni_dialer_sock(d), d, NULL));
}

static int
zt_listener_init(void **epp, nni_url *url, nni_listener *l)
{
	return (zt_ep_init(epp, url, nni_listener_sock(l), NULL, l));
}

static void
zt_ep_close(void *arg)
{
	zt_ep *  ep = arg;
	zt_node *ztn;
	nni_aio *aio;

	nni_aio_abort(ep->ze_creq_aio, NNG_ECLOSED);

	// Cancel any outstanding user operation(s) - they should have
	// been aborted by the above cancellation, but we need to be
	// sure, as the cancellation callback may not have run yet.

	nni_mtx_lock(&zt_lk);
	while ((aio = nni_list_first(&ep->ze_aios)) != NULL) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}

	// Endpoint framework guarantees to only call us once,
	// and to not call other things while we are closed.
	ztn = ep->ze_ztn;
	// If we're on the ztn node list, pull us off.
	if (ztn != NULL) {
		nni_list_node_remove(&ep->ze_link);
		nni_idhash_remove(ztn->zn_ports, ep->ze_laddr & zt_port_mask);
		nni_idhash_remove(ztn->zn_eps, ep->ze_laddr);
	}

	nni_mtx_unlock(&zt_lk);
}

static int
zt_ep_bind_locked(zt_ep *ep)
{
	int      rv;
	uint64_t port;
	uint64_t node;
	zt_node *ztn;

	// If we haven't already got a ZT node, get one.
	if ((ztn = ep->ze_ztn) == NULL) {
		if ((rv = zt_node_find(ep)) != 0) {
			return (rv);
		}
		ztn = ep->ze_ztn;
	}

	node = ep->ze_laddr >> 24;
	if ((node != 0) && (node != ztn->zn_self)) {
		// User requested node id, but it doesn't match our
		// own.
		return (NNG_EADDRINVAL);
	}

	if ((ep->ze_laddr & zt_port_mask) == 0) {
		// ask for an ephemeral port
		if ((rv = nni_idhash_alloc(ztn->zn_ports, &port, ep)) != 0) {
			return (rv);
		}
		NNI_ASSERT(port & zt_ephemeral);
	} else {
		void *conflict;
		// make sure port requested is free.
		port = ep->ze_laddr & zt_port_mask;

		if (nni_idhash_find(ztn->zn_ports, port, &conflict) == 0) {
			return (NNG_EADDRINUSE);
		}
		if ((rv = nni_idhash_insert(ztn->zn_ports, port, ep)) != 0) {
			return (rv);
		}
	}
	NNI_ASSERT(port <= zt_max_port);
	NNI_ASSERT(port > 0);

	ep->ze_laddr = ztn->zn_self;
	ep->ze_laddr <<= 24;
	ep->ze_laddr |= port;
	ep->ze_running = true;

	if ((rv = nni_idhash_insert(ztn->zn_eps, ep->ze_laddr, ep)) != 0) {
		nni_idhash_remove(ztn->zn_ports, port);
		return (rv);
	}

	return (0);
}

static int
zt_ep_bind(void *arg)
{
	int    rv;
	zt_ep *ep = arg;

	nni_mtx_lock(&zt_lk);
	rv = zt_ep_bind_locked(ep);
	nni_mtx_unlock(&zt_lk);

	return (rv);
}

static void
zt_ep_cancel(nni_aio *aio, void *arg, int rv)
{
	zt_ep *ep = arg;

	nni_mtx_lock(&zt_lk);
	if (nni_aio_list_active(aio)) {
		if (ep->ze_aio != NULL) {
			nni_aio_abort(ep->ze_aio, rv);
		}
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&zt_lk);
}

static void
zt_ep_doaccept(zt_ep *ep)
{
	// Call with ep lock held.
	nni_time now;
	zt_pipe *p;
	int      rv;

	now = nni_clock();
	// Consume any timedout connect requests.
	while (ep->ze_creq_tail != ep->ze_creq_head) {
		zt_creq  creq;
		nni_aio *aio;

		creq = ep->ze_creqs[ep->ze_creq_tail % zt_listenq];
		// Discard old connection requests.
		if (creq.cr_expire < now) {
			ep->ze_creq_tail++;
			continue;
		}

		if ((aio = nni_list_first(&ep->ze_aios)) == NULL) {
			// No outstanding accept.  We're done.
			break;
		}

		// We have both conn request, and a place to accept it.

		// Advance the tail.
		ep->ze_creq_tail++;

		// We remove this AIO.  This keeps it from being canceled.
		nni_aio_list_remove(aio);

		rv = zt_pipe_alloc(&p, ep, creq.cr_raddr, ep->ze_laddr, true);
		if (rv != 0) {
			zt_send_err(ep->ze_ztn, ep->ze_nwid, creq.cr_raddr,
			    ep->ze_laddr, zt_err_unknown,
			    "Failed creating pipe");
			nni_aio_finish_error(aio, rv);
			continue;
		}
		p->zp_peer = creq.cr_proto;
		zt_pipe_send_conn_ack(p);
		zt_pipe_start_ping(p);
		nni_aio_set_output(aio, 0, p);
		nni_aio_finish(aio, 0, 0);
	}
}

static void
zt_ep_accept(void *arg, nni_aio *aio)
{
	zt_ep *ep = arg;
	int    rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&zt_lk);
	if ((rv = nni_aio_schedule(aio, zt_ep_cancel, ep)) != 0) {
		nni_mtx_unlock(&zt_lk);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_aio_list_append(&ep->ze_aios, aio);
	zt_ep_doaccept(ep);
	nni_mtx_unlock(&zt_lk);
}

static void
zt_ep_conn_req_cancel(nni_aio *aio, void *arg, int rv)
{
	zt_ep *ep = arg;
	// We don't have much to do here.  The AIO will have been
	// canceled as a result of the "parent" AIO canceling.
	nni_mtx_lock(&zt_lk);
	if (ep->ze_creq_active) {
		ep->ze_creq_active = false;
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&zt_lk);
}

static void
zt_ep_conn_req_cb(void *arg)
{
	zt_ep *  ep = arg;
	zt_pipe *p;
	nni_aio *aio = ep->ze_creq_aio;
	nni_aio *uaio;
	int      rv;

	nni_mtx_lock(&zt_lk);

	ep->ze_creq_active = false;
	switch ((rv = nni_aio_result(aio))) {
	case 0:
		p = nni_aio_get_output(aio, 0);
		// Already canceled, or already handled?
		if ((uaio = nni_list_first(&ep->ze_aios)) != NULL) {
			nni_aio_list_remove(uaio);
			zt_pipe_start_ping(p);
			nni_aio_set_output(uaio, 0, p);
			nni_aio_finish(uaio, 0, 0);
		} else {
			// We have a pipe, but nowhere to stick it.
			// Just discard it.
			zt_pipe_fini(p);
		}
		ep->ze_creq_try = 0;
		break;

	case NNG_ETIMEDOUT:
		if ((ep->ze_creq_try > ep->ze_conn_tries) &&
		    (ep->ze_conn_tries > 0)) {
			// Final timeout attempt.
			if ((uaio = nni_list_first(&ep->ze_aios)) != NULL) {
				nni_aio_list_remove(uaio);
				nni_aio_finish_error(uaio, rv);
				// reset the counter.
				ep->ze_creq_try = 0;
			}
		}
		break;

	default:
		// Failed hard?
		if ((uaio = nni_list_first(&ep->ze_aios)) != NULL) {
			nni_aio_list_remove(uaio);
			nni_aio_finish_error(uaio, rv);
		}
		ep->ze_creq_try = 0;
		break;
	}

	if (nni_list_first(&ep->ze_aios) != NULL) {
		nni_aio_set_timeout(aio, ep->ze_conn_time);
		if (nni_aio_begin(aio) == 0) {
			rv = nni_aio_schedule(aio, zt_ep_conn_req_cancel, ep);
			if (rv != 0) {
				nni_aio_finish_error(aio, rv);
			} else {
				ep->ze_creq_active = true;
				ep->ze_creq_try++;
				zt_ep_send_conn_req(ep);
			}
		}
	}

	nni_mtx_unlock(&zt_lk);
}

static void
zt_ep_connect(void *arg, nni_aio *aio)
{
	zt_ep *ep = arg;
	int    rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	// We bind locally.  We'll use the address later when we give
	// it to the pipe, but this allows us to receive the initial
	// ack back from the server.  (This gives us an ephemeral
	// address to work with.)
	nni_mtx_lock(&zt_lk);

	// Clear the port so we get an ephemeral port.
	ep->ze_laddr &= ~((uint64_t) zt_port_mask);

	if ((rv = zt_ep_bind_locked(ep)) != 0) {
		nni_aio_finish_error(aio, rv);
		nni_mtx_unlock(&zt_lk);
		return;
	}

	if ((ep->ze_raddr >> 24) == 0) {
		ep->ze_raddr |= (ep->ze_ztn->zn_self << zt_port_shift);
	}
	if ((rv = nni_aio_schedule(aio, zt_ep_cancel, ep)) != 0) {
		nni_aio_finish_error(aio, rv);
		nni_mtx_unlock(&zt_lk);
		return;
	}
	nni_aio_list_append(&ep->ze_aios, aio);
	ep->ze_running = true;

	nni_aio_set_timeout(ep->ze_creq_aio, ep->ze_conn_time);
	if (nni_aio_begin(ep->ze_creq_aio) == 0) {
		rv = nni_aio_schedule(
		    ep->ze_creq_aio, zt_ep_conn_req_cancel, ep);
		if (rv != 0) {
			nni_aio_finish_error(ep->ze_creq_aio, rv);
		} else {
			// Send out the first connect message; if not
			// yet attached to network message will be dropped.
			ep->ze_creq_try    = 1;
			ep->ze_creq_active = true;
			zt_ep_send_conn_req(ep);
		}
	}
	nni_mtx_unlock(&zt_lk);
}

static int
zt_ep_set_recvmaxsz(void *arg, const void *data, size_t sz, nni_type t)
{
	zt_ep *ep = arg;
	size_t val;
	int    rv;

	if (((rv = nni_copyin_size(&val, data, sz, 0, NNI_MAXSZ, t)) == 0) &&
	    (ep != NULL)) {
		nni_mtx_lock(&zt_lk);
		ep->ze_rcvmax = val;
		nni_mtx_unlock(&zt_lk);
	}
	return (rv);
}

static int
zt_ep_get_recvmaxsz(void *arg, void *data, size_t *szp, nni_type t)
{
	zt_ep *ep = arg;
	int    rv;
	nni_mtx_lock(&zt_lk);
	rv = nni_copyout_size(ep->ze_rcvmax, data, szp, t);
	nni_mtx_unlock(&zt_lk);
	return (rv);
}

static int
zt_check_string(const void *data, size_t sz, nni_type t)
{
	size_t len;

	if ((t != NNI_TYPE_OPAQUE) && (t != NNI_TYPE_STRING)) {
		return (NNG_EBADTYPE);
	}
	len = nni_strnlen(data, sz);
	if ((len >= sz) || (len >= NNG_MAXADDRLEN)) {
		return (NNG_EINVAL);
	}
	return (0);
}

static int
zt_ep_set_home(void *arg, const void *data, size_t sz, nni_type t)
{
	int    rv;
	zt_ep *ep = arg;

	if (((rv = zt_check_string(data, sz, t)) == 0) && (ep != NULL)) {
		nni_mtx_lock(&zt_lk);
		if (ep->ze_running) {
			rv = NNG_ESTATE;
		} else {
			nni_strlcpy(ep->ze_home, data, sizeof(ep->ze_home));
			if ((rv = zt_node_find(ep)) != 0) {
				ep->ze_ztn = NULL;
			}
		}
		nni_mtx_unlock(&zt_lk);
	}

	return (rv);
}

static int
zt_ep_get_home(void *arg, void *data, size_t *szp, nni_type t)
{
	zt_ep *ep = arg;
	int    rv;

	nni_mtx_lock(&zt_lk);
	rv = nni_copyout_str(ep->ze_home, data, szp, t);
	nni_mtx_unlock(&zt_lk);
	return (rv);
}

static int
zt_ep_get_url(void *arg, void *data, size_t *szp, nni_type t)
{
	char     ustr[64]; // more than plenty
	zt_ep *  ep = arg;
	uint64_t addr;

	nni_mtx_lock(&zt_lk);
	addr = ep->ze_nlistener != NULL ? ep->ze_laddr : ep->ze_raddr;
	snprintf(ustr, sizeof(ustr), "zt://%llx.%llx:%u",
	    (unsigned long long) addr >> zt_port_shift,
	    (unsigned long long) ep->ze_nwid,
	    (unsigned) (addr & zt_port_mask));
	nni_mtx_unlock(&zt_lk);
	return (nni_copyout_str(ustr, data, szp, t));
}

static int
zt_ep_set_orbit(void *arg, const void *data, size_t sz, nni_type t)
{
	uint64_t           moonid;
	uint64_t           peerid;
	zt_ep *            ep = arg;
	int                rv;
	enum ZT_ResultCode zrv;

	if ((t != NNI_TYPE_UINT64) && (t != NNI_TYPE_OPAQUE)) {
		return (NNG_EBADTYPE);
	}
	if (sz == sizeof(uint64_t)) {
		memcpy(&moonid, data, sizeof(moonid));
		peerid = 0;
	} else if (sz == sizeof(uint64_t) * 2) {
		memcpy(&moonid, data, sizeof(moonid));
		memcpy(&peerid, ((char *) data) + sizeof(uint64_t),
		    sizeof(peerid));
	} else {
		return (NNG_EINVAL);
	}
	if (ep == NULL) {
		return (0);
	}

	nni_mtx_lock(&zt_lk);
	if ((ep->ze_ztn == NULL) && ((rv = zt_node_find(ep)) != 0)) {
		nni_mtx_unlock(&zt_lk);
		return (rv);
	}
	zrv = ZT_Node_orbit(ep->ze_ztn->zn_znode, NULL, moonid, peerid);
	nni_mtx_unlock(&zt_lk);

	return (zt_result(zrv));
}

static int
zt_ep_set_deorbit(void *arg, const void *data, size_t sz, nni_type t)
{
	uint64_t moonid;
	zt_ep *  ep = arg;
	int      rv;

	if (((rv = nni_copyin_u64(&moonid, data, sz, t)) == 0) &&
	    (ep != NULL)) {
		enum ZT_ResultCode zrv;

		nni_mtx_lock(&zt_lk);
		if ((ep->ze_ztn == NULL) && ((rv = zt_node_find(ep)) != 0)) {
			nni_mtx_unlock(&zt_lk);
			return (rv);
		}
		zrv = ZT_Node_deorbit(ep->ze_ztn->zn_znode, NULL, moonid);
		nni_mtx_unlock(&zt_lk);
		rv = zt_result(zrv);
	}
	return (rv);
}

static int
zt_ep_set_add_local_addr(void *arg, const void *data, size_t sz, nni_type t)
{
	nng_sockaddr sa;
	zt_ep *      ep = arg;
	int          rv;

	if ((rv = nni_copyin_sockaddr(&sa, data, sz, t)) == 0) {
		enum ZT_ResultCode      zrv;
		zt_node *               ztn;
		struct sockaddr_storage ss;
		struct sockaddr_in *    sin;
		struct sockaddr_in6 *   sin6;

		memset(&ss, 0, sizeof(ss));
		switch (sa.s_family) {
		case NNG_AF_INET:
			sin                  = (void *) &ss;
			sin->sin_family      = AF_INET;
			sin->sin_addr.s_addr = sa.s_in.sa_addr;
			sin->sin_port        = 0;
			break;
		case NNG_AF_INET6:
			sin6              = (void *) &ss;
			sin6->sin6_family = AF_INET6;
			sin6->sin6_port   = 0;
			memcpy(&sin6->sin6_addr, sa.s_in6.sa_addr, 16);
			break;
		default:
			return (NNG_EINVAL);
		}

		if (ep == NULL) {
			return (0);
		}
		nni_mtx_lock(&zt_lk);
		if ((ep->ze_ztn == NULL) && ((rv = zt_node_find(ep)) != 0)) {
			nni_mtx_unlock(&zt_lk);
			return (rv);
		}
		ztn  = ep->ze_ztn;
		zrv = ZT_Node_addLocalInterfaceAddress(ztn->zn_znode, &ss);
		nni_mtx_unlock(&zt_lk);
		rv = zt_result(zrv);
	}
	return (rv);
}

static int
zt_ep_set_clear_local_addrs(void *arg, const void *data, size_t sz, nni_type t)
{
	zt_ep *ep = arg;
	NNI_ARG_UNUSED(data);
	NNI_ARG_UNUSED(sz);
	NNI_ARG_UNUSED(t);

	if (ep != NULL) {
		int      rv;
		ZT_Node *zn;
		nni_mtx_lock(&zt_lk);
		if ((ep->ze_ztn == NULL) && ((rv = zt_node_find(ep)) != 0)) {
			nni_mtx_unlock(&zt_lk);
			return (rv);
		}
		zn = ep->ze_ztn;
		ZT_Node_clearLocalInterfaceAddresses(zn);
		nni_mtx_unlock(&zt_lk);
	}
	return (0);
}

static int
zt_ep_get_node(void *arg, void *data, size_t *szp, nni_type t)
{
	zt_ep *ep = arg;
	int    rv;

	nni_mtx_lock(&zt_lk);
	if ((ep->ze_ztn == NULL) && ((rv = zt_node_find(ep)) != 0)) {
		nni_mtx_unlock(&zt_lk);
		return (rv);
	}

	rv = nni_copyout_u64(ep->ze_ztn->zn_self, data, szp, t);

	nni_mtx_unlock(&zt_lk);
	return (rv);
}

static int
zt_ep_get_nwid(void *arg, void *data, size_t *szp, nni_type t)
{
	zt_ep *ep = arg;
	int    rv;

	nni_mtx_lock(&zt_lk);
	if ((ep->ze_ztn == NULL) && ((rv = zt_node_find(ep)) != 0)) {
		nni_mtx_unlock(&zt_lk);
		return (rv);
	}
	rv = nni_copyout_u64(ep->ze_nwid, data, szp, t);
	nni_mtx_unlock(&zt_lk);
	return (rv);
}

static int
zt_ep_get_nw_name(void *arg, void *buf, size_t *szp, nni_type t)
{
	zt_ep *ep = arg;
	int    rv;

	nni_mtx_lock(&zt_lk);
	if ((ep->ze_ztn == NULL) && ((rv = zt_node_find(ep)) != 0)) {
		nni_mtx_unlock(&zt_lk);
		return (rv);
	}
	rv = zt_get_nw_name(ep->ze_ztn, ep->ze_nwid, buf, szp, t);
	nni_mtx_unlock(&zt_lk);
	return (rv);
}

static int
zt_ep_get_nw_status(void *arg, void *buf, size_t *szp, nni_type t)
{
	zt_ep *ep = arg;
	int    rv;
	int    status;

	nni_mtx_lock(&zt_lk);
	if ((ep->ze_ztn == NULL) && ((rv = zt_node_find(ep)) != 0)) {
		nni_mtx_unlock(&zt_lk);
		return (rv);
	}
	if ((rv = zt_get_nw_status(ep->ze_ztn, ep->ze_nwid, &status)) != 0) {
		nni_mtx_unlock(&zt_lk);
		return (rv);
	}
	nni_mtx_unlock(&zt_lk);
	return (nni_copyout_int(status, buf, szp, t));
}

static int
zt_ep_set_ping_time(void *arg, const void *data, size_t sz, nni_type t)
{
	zt_ep *      ep = arg;
	nng_duration val;
	int          rv;

	if (((rv = nni_copyin_ms(&val, data, sz, t)) == 0) && (ep != NULL)) {
		nni_mtx_lock(&zt_lk);
		ep->ze_ping_time = val;
		nni_mtx_unlock(&zt_lk);
	}
	return (rv);
}

static int
zt_ep_get_ping_time(void *arg, void *data, size_t *szp, nni_type t)
{
	zt_ep *ep = arg;
	int    rv;

	nni_mtx_lock(&zt_lk);
	rv = nni_copyout_ms(ep->ze_ping_time, data, szp, t);
	nni_mtx_unlock(&zt_lk);
	return (rv);
}

static int
zt_ep_set_ping_tries(void *arg, const void *data, size_t sz, nni_type t)
{
	zt_ep *ep = arg;
	int    val;
	int    rv;

	if (((rv = nni_copyin_int(&val, data, sz, 0, 1000000, t)) == 0) &&
	    (ep != NULL)) {
		nni_mtx_lock(&zt_lk);
		ep->ze_ping_tries = val;
		nni_mtx_unlock(&zt_lk);
	}
	return (rv);
}

static int
zt_ep_get_ping_tries(void *arg, void *data, size_t *szp, nni_type t)
{
	zt_ep *ep = arg;
	int    rv;

	nni_mtx_lock(&zt_lk);
	rv = nni_copyout_int(ep->ze_ping_tries, data, szp, t);
	nni_mtx_unlock(&zt_lk);
	return (rv);
}

static int
zt_ep_set_conn_time(void *arg, const void *data, size_t sz, nni_type t)
{
	zt_ep *      ep = arg;
	nng_duration val;
	int          rv;

	if (((rv = nni_copyin_ms(&val, data, sz, t)) == 0) && (ep != NULL)) {
		nni_mtx_lock(&zt_lk);
		ep->ze_conn_time = val;
		nni_mtx_unlock(&zt_lk);
	}
	return (rv);
}

static int
zt_ep_get_conn_time(void *arg, void *data, size_t *szp, nni_type t)
{
	zt_ep *ep = arg;
	int    rv;

	nni_mtx_lock(&zt_lk);
	rv = nni_copyout_ms(ep->ze_conn_time, data, szp, t);
	nni_mtx_unlock(&zt_lk);
	return (rv);
}

static int
zt_ep_set_conn_tries(void *arg, const void *data, size_t sz, nni_type t)
{
	zt_ep *ep = arg;
	int    val;
	int    rv;

	if (((rv = nni_copyin_int(&val, data, sz, 0, 1000000, t)) == 0) &&
	    (ep != NULL)) {
		nni_mtx_lock(&zt_lk);
		ep->ze_conn_tries = val;
		nni_mtx_unlock(&zt_lk);
	}
	return (rv);
}

static int
zt_ep_get_conn_tries(void *arg, void *data, size_t *szp, nni_type t)
{
	zt_ep *ep = arg;
	int    rv;

	nni_mtx_lock(&zt_lk);
	rv = nni_copyout_int(ep->ze_conn_tries, data, szp, t);
	nni_mtx_unlock(&zt_lk);
	return (rv);
}

static int
zt_ep_get_locaddr(void *arg, void *data, size_t *szp, nni_type t)
{
	zt_ep *      ep = arg;
	nng_sockaddr sa;

	memset(&sa, 0, sizeof(sa));
	sa.s_zt.sa_family = NNG_AF_ZT;
	nni_mtx_lock(&zt_lk);
	sa.s_zt.sa_nwid   = ep->ze_nwid;
	sa.s_zt.sa_nodeid = ep->ze_laddr >> zt_port_shift;
	sa.s_zt.sa_port   = ep->ze_laddr & zt_port_mask;
	nni_mtx_unlock(&zt_lk);
	return (nni_copyout_sockaddr(&sa, data, szp, t));
}

static int
zt_pipe_get_locaddr(void *arg, void *data, size_t *szp, nni_type t)
{
	zt_pipe *    p = arg;
	nng_sockaddr sa;

	memset(&sa, 0, sizeof(sa));
	sa.s_zt.sa_family = NNG_AF_ZT;
	sa.s_zt.sa_nwid   = p->zp_nwid;
	sa.s_zt.sa_nodeid = p->zp_laddr >> zt_port_shift;
	sa.s_zt.sa_port   = p->zp_laddr & zt_port_mask;
	return (nni_copyout_sockaddr(&sa, data, szp, t));
}

static int
zt_pipe_get_remaddr(void *arg, void *data, size_t *szp, nni_type t)
{
	zt_pipe *    p = arg;
	nng_sockaddr sa;

	memset(&sa, 0, sizeof(sa));
	sa.s_zt.sa_family = NNG_AF_ZT;
	sa.s_zt.sa_nwid   = p->zp_nwid;
	sa.s_zt.sa_nodeid = p->zp_raddr >> zt_port_shift;
	sa.s_zt.sa_port   = p->zp_raddr & zt_port_mask;
	return (nni_copyout_sockaddr(&sa, data, szp, t));
}

static int
zt_pipe_get_mtu(void *arg, void *data, size_t *szp, nni_type t)
{
	zt_pipe *p = arg;
	return (nni_copyout_size(p->zp_mtu, data, szp, t));
}

static const nni_option zt_pipe_options[] = {
	{
	    .o_name = NNG_OPT_LOCADDR,
	    .o_get  = zt_pipe_get_locaddr,
	},
	{
	    .o_name = NNG_OPT_REMADDR,
	    .o_get  = zt_pipe_get_remaddr,
	},
	{
	    .o_name = NNG_OPT_ZT_MTU,
	    .o_get  = zt_pipe_get_mtu,
	},
	{
	    .o_name = NNG_OPT_ZT_NWID,
	    .o_get  = zt_pipe_get_nwid,
	},
	{
	    .o_name = NNG_OPT_ZT_NODE,
	    .o_get  = zt_pipe_get_node,
	},
	{
	    .o_name = NNG_OPT_RECVMAXSZ,
	    .o_get  = zt_pipe_get_recvmaxsz,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static int
zt_pipe_getopt(void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	zt_pipe *p = arg;
	return (nni_getopt(zt_pipe_options, name, p, buf, szp, t));
}

static nni_tran_pipe_ops zt_pipe_ops = {
	.p_init   = zt_pipe_init,
	.p_fini   = zt_pipe_fini,
	.p_send   = zt_pipe_send,
	.p_recv   = zt_pipe_recv,
	.p_close  = zt_pipe_close,
	.p_peer   = zt_pipe_peer,
	.p_getopt = zt_pipe_getopt,
};

static nni_option zt_dialer_options[] = {
	{
	    .o_name = NNG_OPT_RECVMAXSZ,
	    .o_get  = zt_ep_get_recvmaxsz,
	    .o_set  = zt_ep_set_recvmaxsz,
	},
	{
	    .o_name = NNG_OPT_URL,
	    .o_get  = zt_ep_get_url,
	},
	{
	    .o_name = NNG_OPT_ZT_HOME,
	    .o_get  = zt_ep_get_home,
	    .o_set  = zt_ep_set_home,
	},
	{
	    .o_name = NNG_OPT_ZT_NODE,
	    .o_get  = zt_ep_get_node,
	},
	{
	    .o_name = NNG_OPT_ZT_NWID,
	    .o_get  = zt_ep_get_nwid,
	},
	{
	    .o_name = NNG_OPT_ZT_NETWORK_STATUS,
	    .o_get  = zt_ep_get_nw_status,
	},
	{
	    .o_name = NNG_OPT_ZT_NETWORK_NAME,
	    .o_get  = zt_ep_get_nw_name,
	},
	{
	    .o_name = NNG_OPT_ZT_PING_TIME,
	    .o_get  = zt_ep_get_ping_time,
	    .o_set  = zt_ep_set_ping_time,
	},
	{
	    .o_name = NNG_OPT_ZT_PING_TRIES,
	    .o_get  = zt_ep_get_ping_tries,
	    .o_set  = zt_ep_set_ping_tries,
	},
	{
	    .o_name = NNG_OPT_ZT_CONN_TIME,
	    .o_get  = zt_ep_get_conn_time,
	    .o_set  = zt_ep_set_conn_time,
	},
	{
	    .o_name = NNG_OPT_ZT_CONN_TRIES,
	    .o_get  = zt_ep_get_conn_tries,
	    .o_set  = zt_ep_set_conn_tries,
	},
	{
	    .o_name = NNG_OPT_ZT_ORBIT,
	    .o_set  = zt_ep_set_orbit,
	},
	{
	    .o_name = NNG_OPT_ZT_DEORBIT,
	    .o_set  = zt_ep_set_deorbit,
	},
	{
	    .o_name = NNG_OPT_ZT_ADD_LOCAL_ADDR,
	    .o_set  = zt_ep_set_add_local_addr,
	},
	{
	    .o_name = NNG_OPT_ZT_CLEAR_LOCAL_ADDRS,
	    .o_set  = zt_ep_set_clear_local_addrs,
	},

	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_option zt_listener_options[] = {
	{
	    .o_name = NNG_OPT_RECVMAXSZ,
	    .o_get  = zt_ep_get_recvmaxsz,
	    .o_set  = zt_ep_set_recvmaxsz,
	},
	{
	    .o_name = NNG_OPT_URL,
	    .o_get  = zt_ep_get_url,
	},
	{
	    .o_name = NNG_OPT_ZT_HOME,
	    .o_get  = zt_ep_get_home,
	    .o_set  = zt_ep_set_home,
	},
	{
	    .o_name = NNG_OPT_ZT_NODE,
	    .o_get  = zt_ep_get_node,
	},
	{
	    .o_name = NNG_OPT_ZT_NWID,
	    .o_get  = zt_ep_get_nwid,
	},
	{
	    .o_name = NNG_OPT_ZT_NETWORK_STATUS,
	    .o_get  = zt_ep_get_nw_status,
	},
	{
	    .o_name = NNG_OPT_ZT_NETWORK_NAME,
	    .o_get  = zt_ep_get_nw_name,
	},
	{
	    .o_name = NNG_OPT_ZT_PING_TIME,
	    .o_get  = zt_ep_get_ping_time,
	    .o_set  = zt_ep_set_ping_time,
	},
	{
	    .o_name = NNG_OPT_ZT_PING_TRIES,
	    .o_get  = zt_ep_get_ping_tries,
	    .o_set  = zt_ep_set_ping_tries,
	},
	{
	    .o_name = NNG_OPT_ZT_ORBIT,
	    .o_set  = zt_ep_set_orbit,
	},
	{
	    .o_name = NNG_OPT_ZT_DEORBIT,
	    .o_set  = zt_ep_set_deorbit,
	},
	{
	    .o_name = NNG_OPT_LOCADDR,
	    .o_get  = zt_ep_get_locaddr,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_tran_dialer_ops zt_dialer_ops = {
	.d_init    = zt_dialer_init,
	.d_fini    = zt_ep_fini,
	.d_connect = zt_ep_connect,
	.d_close   = zt_ep_close,
	.d_options = zt_dialer_options,
};

static nni_tran_listener_ops zt_listener_ops = {
	.l_init    = zt_listener_init,
	.l_fini    = zt_ep_fini,
	.l_bind    = zt_ep_bind,
	.l_accept  = zt_ep_accept,
	.l_close   = zt_ep_close,
	.l_options = zt_listener_options,
};

// This is the ZeroTier transport linkage, and should be the
// only global symbol in this entire file.
static struct nni_tran zt_tran = {
	.tran_version  = NNI_TRANSPORT_VERSION,
	.tran_scheme   = "zt",
	.tran_dialer   = &zt_dialer_ops,
	.tran_listener = &zt_listener_ops,
	.tran_pipe     = &zt_pipe_ops,
	.tran_init     = zt_tran_init,
	.tran_fini     = zt_tran_fini,
};

int
nng_zt_register(void)
{
	return (nni_tran_register(&zt_tran));
}
