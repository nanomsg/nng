//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "nng/nng.h"
#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <io.h>
#include <windows.h>
#include <winsock2.h>
#else
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TEST_NO_MAIN
#include "nuts.h"

void
nuts_scratch_addr(const char *scheme, size_t sz, char *addr)
{
	if ((strcmp(scheme, "inproc") == 0) ||
	    (strcmp(scheme, "abstract") == 0)) {
		(void) snprintf(addr, sz, "%s://nuts%04x%04x%04x%04x", scheme,
		    nng_random(), nng_random(), nng_random(), nng_random());
		return;
	}

	if ((strncmp(scheme, "tcp", 3) == 0) ||
	    (strncmp(scheme, "tls", 3) == 0) ||
	    (strncmp(scheme, "udp", 3) == 0)) {
		(void) snprintf(
		    addr, sz, "%s://127.0.0.1:%u", scheme, nuts_next_port());
		return;
	}

	if (strncmp(scheme, "ws", 2) == 0) {
		(void) snprintf(addr, sz,
		    "%s://127.0.0.1:%u/nuts%04x%04x%04x%04x", scheme,
		    nuts_next_port(), nng_random(), nng_random(), nng_random(),
		    nng_random());
		return;
	}

	if ((strncmp(scheme, "ipc", 3) == 0) ||
	    (strncmp(scheme, "unix", 4) == 0)) {
#ifdef _WIN32
		// Windows doesn't place IPC names in the filesystem.
		(void) snprintf(addr, sz, "%s://nuts%04x%04x%04x%04x", scheme,
		    nng_random(), nng_random(), nng_random(), nng_random());
		return;
#else
		char *tmpdir;

		if (((tmpdir = getenv("TMPDIR")) == NULL) &&
		    ((tmpdir = getenv("TEMP")) == NULL) &&
		    ((tmpdir = getenv("TMP")) == NULL)) {
			tmpdir = "/tmp";
		}

		(void) snprintf(addr, sz, "%s://%s/nuts%04x%04x%04x%04x",
		    scheme, tmpdir, nng_random(), nng_random(), nng_random(),
		    nng_random());
		return;
#endif
	}

	// We should not be here.
	nng_log_err("NUTS", "Unknown scheme");
	abort();
}

// nuts_next_port returns a "next" allocation port.
// Ports are chosen by starting from a random point within a
// range (normally 38000-40000, but other good places to choose
// might be 36000-37000, 42000-43000, 45000-47000, 48000-49000.
// These are non-ephemeral ports.  Successive calls to this function
// will return the next port in the range (wrapping).  This works even
// across process boundaries, as the range is tracked in a file named
// by $TEST_PORT_FILE.  The range of ports can be configured by using
// $TEST_PORT_RANGE (the range is specified as "lo:hi" where the actual
// port will be in the range [lo,hi).
uint16_t
nuts_next_port(void)
{
	char    *name;
	FILE    *f;
	uint16_t port;
	uint16_t base;
	uint16_t end;
	char    *str;
#ifdef _WIN32
	OVERLAPPED olp;
	HANDLE     h;
#endif

	if ((name = getenv("NUTS_PORT_FILE")) == NULL) {
		name = ".nuts_ports";
	}
	if (((str = getenv("NUTS_PORT_RANGE")) == NULL) ||
	    ((sscanf(str, "%hu:%hu", &base, &end)) != 1) ||
	    ((int) end - (int) base) < 1) {
		base = 38000;
		end  = 40000;
	}

	if (((f = fopen(name, "r+")) == NULL) &&
	    ((f = fopen(name, "w+")) == NULL)) {
		return (0);
	}
	(void) fseek(f, 0, SEEK_SET);

#ifdef _WIN32
	h = (HANDLE) _get_osfhandle(_fileno(f));

	// This contains the offset information for LockFileEx.
	ZeroMemory(&olp, sizeof(olp));

	if (LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK, 0, MAXDWORD, MAXDWORD,
	        &olp) == FALSE) {
		fclose(f);
		return (0);
	}
#else
	if (lockf(fileno(f), 0, F_LOCK) != 0) {
		(void) fclose(f);
		return (0);
	}
#endif
	if (fscanf(f, "%hu", &port) != 1) {
		unsigned seed = (unsigned) time(NULL);

#ifdef _WIN32
		port = base + rand_s(&seed) % (end - base);
#else
		port = base + rand_r(&seed) % (end - base);
#endif
	}
	port++;
	if ((port < base) || (port >= (base + end))) {
		port = base;
	}

#ifdef _WIN32
	fseek(f, 0, SEEK_SET);
	SetEndOfFile(h);
	(void) fprintf(f, "%u", port);
	ZeroMemory(&olp, sizeof(olp));
	(void) UnlockFileEx(h, 0, MAXDWORD, MAXDWORD, &olp);
#else
	fseek(f, 0, SEEK_SET);
	if (ftruncate(fileno(f), 0) != 0) {
		(void) fclose(f);
		return (0);
	}

	(void) fprintf(f, "%u", port);
	(void) lockf(fileno(f), 0, F_ULOCK);

#endif
	(void) fclose(f);
	return (port);
}

struct marriage_notice {
	nng_mtx *mx;
	nng_cv  *cv;
	int      s1;
	int      s2;
	int      cnt1;
	int      cnt2;
	nng_pipe p1;
	nng_pipe p2;
};

static void
married(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	struct marriage_notice *notice = arg;
	(void) ev;

	nng_mtx_lock(notice->mx);
	if (nng_socket_id(nng_pipe_socket(p)) == notice->s1) {
		notice->cnt1++;
		notice->p1 = p;
	} else if (nng_socket_id(nng_pipe_socket(p)) == notice->s2) {
		notice->cnt2++;
		notice->p2 = p;
	}
	nng_cv_wake(notice->cv);
	nng_mtx_unlock(notice->mx);
}

int
nuts_marry(nng_socket s1, nng_socket s2)
{
	return (nuts_marry_ex(s1, s2, NULL, NULL, NULL));
}

// NB: This function is always called with sufficient space to
// hold the resulting expansion.
static void
replace_port_zero(const char *addr, char *buf, int port)
{
	int  i;
	int  j;
	bool colon = false;
	char c;

	for (i = 0, j = 0; (c = addr[i]) != '\0'; i++) {

		if (colon && c == '0') {
			char num[16];
			(void) snprintf(num, sizeof(num), "%d", port);
			memcpy(&buf[j], num, strlen(num));
			j += (int) strlen(num);
			colon = false;
			continue;
		}
		colon    = c == ':';
		buf[j++] = c;
	}
	buf[j] = '\0';
}

int
nuts_marry_ex(
    nng_socket s1, nng_socket s2, const char *url, nng_pipe *p1, nng_pipe *p2)
{
	struct marriage_notice note;
	nng_time               timeout;
	int                    rv;
	char                   addr[64];
	nng_listener           l;
	int                    port;
	int                    fd[2];

	if (url == NULL) {
		(void) snprintf(addr, sizeof(addr),
		    "inproc://marry%04x%04x%04x%04x", nng_random(),
		    nng_random(), nng_random(), nng_random());
		url = addr;
	}

	note.cnt1 = 0;
	note.cnt2 = 0;
	note.s1   = nng_socket_id(s1);
	note.s2   = nng_socket_id(s2);
	timeout   = nng_clock() + 1000; // 1 second

	if (((rv = nng_mtx_alloc(&note.mx)) != 0) ||
	    ((rv = nng_cv_alloc(&note.cv, note.mx)) != 0) ||
	    ((rv = nng_pipe_notify(
	          s1, NNG_PIPE_EV_ADD_POST, married, &note)) != 0) ||
	    ((rv = nng_pipe_notify(
	          s2, NNG_PIPE_EV_ADD_POST, married, &note)) != 0)) {
		goto done;
	}

	// If socket:// is requested we will try to use that, otherwise we
	// fake it with a TCP loopback socket.
	if (strcmp(url, "socket://") == 0) {
		rv = nng_socket_pair(fd);
		if (rv == 0) {
			nng_listener l2;
			if (((rv = nng_listen(s1, url, &l, 0)) != 0) ||
			    ((rv = nng_listen(s2, url, &l2, 0)) != 0) ||
			    ((rv = nng_listener_set_int(
			          l, NNG_OPT_SOCKET_FD, fd[0])) != 0) ||
			    ((rv = nng_listener_set_int(
			          l2, NNG_OPT_SOCKET_FD, fd[1])) != 0)) {
#ifdef _WIN32
				_close(fd[0]);
				_close(fd[1]);
#else
				close(fd[0]);
				close(fd[1]);
#endif
				return (rv);
			}
		} else if (rv == NNG_ENOTSUP) {
			url = "tcp://127.0.0.1:0";
			rv  = 0;
		} else {
			return (rv);
		}
	}

	if (strcmp(url, "socket://") != 0) {
		if ((rv = nng_listen(s1, url, &l, 0)) != 0) {
			return (rv);
		}
	}
	if ((strstr(url, ":0") != NULL) &&
	    // If a TCP port of zero was selected, let's ask for the actual
	    // port bound.
	    (nng_listener_get_int(l, NNG_OPT_TCP_BOUND_PORT, &port) == 0) &&
	    (port > 0)) {
		replace_port_zero(url, addr, port);
		url = addr;
	}
	if (((rv = nng_socket_set_ms(s2, NNG_OPT_RECONNMINT, 10)) != 0) ||
	    ((rv = nng_socket_set_ms(s2, NNG_OPT_RECONNMAXT, 10)) != 0)) {
		goto done;
	}
	if ((strcmp(url, "socket://") != 0) &&
	    ((rv = nng_dial(s2, url, NULL, 0)) != 0)) {
		goto done;
	}

	nng_mtx_lock(note.mx);
	while ((note.cnt1 == 0) || (note.cnt2 == 0)) {
		if ((rv = nng_cv_until(note.cv, timeout)) != 0) {
			break;
		}
	}
	nng_mtx_unlock(note.mx);
	if (p1 != NULL) {
		*p1 = note.p1;
	}
	if (p2 != NULL) {
		*p2 = note.p2;
	}

done:
	nng_pipe_notify(s1, NNG_PIPE_EV_ADD_POST, NULL, NULL);
	nng_pipe_notify(s2, NNG_PIPE_EV_ADD_POST, NULL, NULL);
	if (note.cv != NULL) {
		nng_cv_free(note.cv);
	}
	if (note.mx != NULL) {
		nng_mtx_free(note.mx);
	}
	return (rv);
}
