//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_TRANSPORT_ZEROTIER_ZEROTIER_H
#define NNG_TRANSPORT_ZEROTIER_ZEROTIER_H

#include <nng/nng.h>

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
// The ZeroTier URL format we support is zt://<ztid>.<nwid>:<port> where
// the <nwid> component represents the 64-bit hexadecimal ZeroTier
// network ID,the <ztid> represents the 40-bit hexadecimal ZeroTier
// node (device) ID, and the <port> is a 24-bit (decimal) port number.
//
// A listener may replace the <ztid> with a wildcard, to just bind to itself,
// in which case the format will be zt://*.<nwid>:<port>
//
// A listener may also use either 0 or * for the <port> to indicate that
// a random local ephemeral port should be used.
//
// Because ZeroTier takes a while to establish connectivity, it is even
// more important that applications using the ZeroTier transport not
// assume that a connection will be immediately available.  It can take
// quite a few seconds for peer-to-peer connectivity to be established.
//
// The ZeroTier transport was funded by Capitar IT Group, BV.
//
// The protocol itself is documented online at:
// http://nanomsg.org/rfcs/sp-zerotier-v0.html
//
// This transport is highly experimental.

// ZeroTier transport-specific options.

// NNG_OPT_ZT_HOME is a string containing a directory, where persistent
// state (key files, etc.) will be stored.  It should be protected from
// unauthorized viewing and modification.  This option must be set on an
// endpoint or socket before the endpoint(s) are started.  If the unset,
// or an empty string, then no persistence is used and an ephemeral node
// will be created instead.  Note that different endpoints may use different
// values for this option, and that will lead to each endpoint having a
// different ZeroTier identity -- however only one ephemeral node will
// be created for the application.
#define NNG_OPT_ZT_HOME "zt:home"

// NNG_OPT_ZT_NWID is the 64-bit network ID, represented using a uint64_t in
// native byte order.  This is a read-only option; it is derived automatically
// from the URL.
#define NNG_OPT_ZT_NWID "zt:nwid"

// NNG_OPT_ZT_NODE is the 40-bit node ID, stored in native order in the low
// 40-bits of a uint64_t, of the node.  This is a read-only option.
#define NNG_OPT_ZT_NODE "zt:node"

// NNG_OPT_ZT_NETWORK_STATUS represents the status of the ZeroTier virtual
// network.  The option is a read-only value, stored as an integer, which
// takes of the nng_zt_network_status_xxx values listed below.
#define NNG_OPT_ZT_NETWORK_STATUS "zt:network-status"

// NNG_OPT_ZT_NETWORK_NAME is a human-readable name for the ZeroTier virtual
// network.  This will only be set once the ZeroTier network has come up
// as the name comes from the network controller.  This is read-only, and
// is presented as an ASCIIZ string.
#define NNG_OPT_ZT_NETWORK_NAME "zt:network-name"

// NNG_OPT_ZT_PING_TIME and NNG_OPT_ZT_PING_TRIES are used to send ping
// requests when a connection appears to be idled.  If a logical session
// has not received traffic from it's peer for ping-time, then a ping packet
// is sent.  This will be done up to ping-count times.  If no traffic from
// the remote peer is seen after all ping requests are sent, then the peer
// is assumed to be dead or offline, and the session is closed.  The
// NNG_OPT_ZT_PING_TIME is a duration (msec, stored as an nng_duration, and
// NNG_OPT_ZT_PING_COUNT is an integer.)  This ping process can be disabled
// by setting either ping-time or ping-count to zero.
#define NNG_OPT_ZT_PING_TIME "zt:ping-time"
#define NNG_OPT_ZT_PING_TRIES "zt:ping-tries"

// NNG_OPT_ZT_CONN_TIME and NNG_OPT_ZT_CONN_TRIES are used to control
// the interval between connection attempts, and the maximum number of
// connection attempts to make before assuming that the peer is absent
// (and returning NNG_ETIMEDOUT).  The NNG_OPT_ZT_CONN_TIME is a duration,
// the NNG_OPT_ZT_CONN_TRIES is an integer.
#define NNG_OPT_ZT_CONN_TIME "zt:conn-time"
#define NNG_OPT_ZT_CONN_TRIES "zt:conn-tries"

// NNG_OPT_ZT_MTU is a read-only size_t and contains the ZeroTier virtual
// network MTU (i.e. the L2 payload MTU). Messages that are larger than this
// (including our 20-byte header data) will be fragmented into multiple
// virtual L2 frames.
#define NNG_OPT_ZT_MTU "zt:mtu"

// NNG_OPT_ZT_ORBIT is a write-only API to add a "moon" -- this affects the
// endpoint, and all other endpoints using the same node. The value is
// a pair of 64-bit integers -- the first is the moon ID, and the second, if
// non-zero, is the node ID of a server.  Conventionally this is the same
// as the moon ID.
#define NNG_OPT_ZT_ORBIT "zt:orbit"

// NNG_OPT_ZT_DEORBIT removes the moon ID from the node, so that it will
// no longer use that moon.  The argument is a moon ID to remove.  If the
// node is not already orbiting, then this operation does nothing.
#define NNG_OPT_ZT_DEORBIT "zt:deorbit"

// NNG_OPT_ZT_ADD_LOCAL_ADDR adds the local address (IP address) as
// local interface address.  This facilitates the local startup and
// discovery.  Note that this can be called multiple times to add
// additional address.  This is optional, and usually not needed.
// The value is an nng_sockaddr corresponding to an IP (or IPv6) address.
#define NNG_OPT_ZT_ADD_LOCAL_ADDR "zt:add-local-addr"

// NNG_OPT_ZT_CLEAR_LOCAL_ADDRS clears ZeroTier's notion of all
// local addresses.  This may be useful when used on a mobile node,
// to reset the notion of what the local addresses are.  This
// option takes no argument really.
#define NNG_OPT_ZT_CLEAR_LOCAL_ADDRS "zt:clear-local-addrs"

#ifdef __cplusplus
extern "C" {
#endif

// Network status values.
// These values are supplied to help folks checking status.  They are the
// return values from zt_opt_status.  We avoid hard coding them as defines,
// to keep applications from baking in values that may change if the
// underlying ZeroTier transport changes.
enum nng_zt_status {
	NNG_ZT_STATUS_UP,
	NNG_ZT_STATUS_CONFIG,
	NNG_ZT_STATUS_DENIED,
	NNG_ZT_STATUS_NOTFOUND,
	NNG_ZT_STATUS_ERROR,
	NNG_ZT_STATUS_OBSOLETE,
	NNG_ZT_STATUS_UNKNOWN,
};

NNG_DECL int nng_zt_register(void);

#ifdef __cplusplus
}
#endif

#endif // NNG_TRANSPORT_ZEROTIER_ZEROTIER_H
