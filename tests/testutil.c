//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
// order counts
#include <mswsock.h>
#define poll WSAPoll
#include <io.h>
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

#if !defined(_WIN32) && !defined(CLOCK_MONOTONIC)
#include <poll.h>
#endif

#include "testutil.h"

#include <nng/supplemental/util/platform.h>

uint64_t
testutil_clock(void)
{
#ifdef _WIN32
	return (GetTickCount64());
#elif defined(CLOCK_MONTONIC)
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	uint64_t val;

	val = ts.tv_sec;
	val *= 1000;
	val += ts.tv_nsec / 1000000;
	return (val);
#else
	static time_t  epoch;
	struct timeval tv;

	if (epoch == 0) {
		epoch = time(NULL);
	}
	gettimeofday(&tv, NULL);

	if (tv.tv_sec < epoch) {
		// Broken clock.
		// This will force all other timing tests to fail
		return (0);
	}
	tv.tv_sec -= epoch;
	return (
	    ((uint64_t)(tv.tv_sec) * 1000) + (uint64_t)(tv.tv_usec / 1000));
#endif

#ifdef _WIN32
#else
#include <fcntl.h>
#include <unistd.h>
#endif
}

bool
testutil_pollfd(int fd)
{
#ifdef _WIN32
	struct pollfd pfd;
	pfd.fd      = (SOCKET) fd;
	pfd.events  = POLLRDNORM;
	pfd.revents = 0;

	switch (WSAPoll(&pfd, 1, 0)) {
	case 0:
		return (false);
	case 1:
		return (true);
	}
#else
	struct pollfd pfd;

	pfd.fd      = fd;
	pfd.events  = POLLRDNORM;
	pfd.revents = 0;

	switch (poll(&pfd, 1, 0)) {
	case 0:
		return (false);
	case 1:
		return (true);
	}
#endif
	return (false);
}

uint16_t
testutil_htons(uint16_t in)
{
#ifdef NNG_LITTLE_ENDIAN
	in = ((in >> 8u) & 0xffu) | ((in & 0xffu) << 8u);
#endif
	return (in);
}

uint32_t
testutil_htonl(uint32_t in)
{
#ifdef NNG_LITTLE_ENDIAN
	in = ((in >> 24u) & 0xffu) | ((in >> 8u) & 0xff00u) |
	    ((in << 8u) & 0xff0000u) | ((in << 24u) & 0xff000000u);
#endif
	return (in);
}

void
testutil_scratch_addr(const char *scheme, size_t sz, char *addr)
{
	if (strcmp(scheme, "inproc") == 0) {
		(void) snprintf(addr, sz, "%s://testutil%04x%04x%04x%04x",
		    scheme, nng_random(), nng_random(), nng_random(),
		    nng_random());
		return;
	}

	if ((strncmp(scheme, "tcp", 3) == 0) ||
	    (strncmp(scheme, "tls", 3) == 0)) {
		(void) snprintf(addr, sz, "%s://127.0.0.1:%u", scheme,
		    testutil_next_port());
		return;
	}

	if (strncmp(scheme, "ws", 2) == 0) {
		(void) snprintf(addr, sz,
		    "%s://127.0.0.1:%u/testutil%04x%04x%04x%04x", scheme,
		    testutil_next_port(), nng_random(), nng_random(),
		    nng_random(), nng_random());
		return;
	}

	if (strncmp(scheme, "ipc", 3) == 0) {
#ifdef _WIN32
		// Windows doesn't place IPC names in the filesystem.
		(void) snprintf(addr, sz, "%s://testutil%04x%04x%04x%04x",
		    scheme, nng_random(), nng_random(), nng_random(),
		    nng_random());
		return;
#else
		char *tmpdir;

		if (((tmpdir = getenv("TMPDIR")) == NULL) &&
		    ((tmpdir = getenv("TEMP")) == NULL) &&
		    ((tmpdir = getenv("TMP")) == NULL)) {
			tmpdir = "/tmp";
		}

		(void) snprintf(addr, sz, "%s://%s/testutil%04x%04x%04x%04x",
		    scheme, tmpdir, nng_random(), nng_random(), nng_random(),
		    nng_random());
		return;
#endif
	}

	// We should not be here.
	abort();
}

// testutil_next_port returns a "next" allocation port.
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
testutil_next_port(void)
{
	char *   pfile;
	FILE *   f;
	uint16_t port;
	uint16_t base;
	uint16_t end;
	char *   str;
#ifdef _WIN32
	OVERLAPPED olp;
	HANDLE     h;
#endif

	pfile = getenv("TEST_PORT_FILE");
	if (pfile == NULL) {
		pfile = ".nng_ports";
	}
	if (((str = getenv("TEST_PORT_RANGE")) == NULL) ||
	    ((sscanf(str, "%hu:%hu", &base, &end)) != 1) ||
	    ((int) end - (int) base) < 1) {
		base = 38000;
		end  = 40000;
	}

	if (((f = fopen(pfile, "r+")) == NULL) &&
	    ((f = fopen(pfile, "w+")) == NULL)) {
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
	(void) ftruncate(fileno(f), 0);

	(void) fprintf(f, "%u", port);
	(void) lockf(fileno(f), 0, F_ULOCK);

#endif
	(void) fclose(f);
	return (port);
}

void
testutil_sleep(int msec)
{
#ifdef _WIN32
	Sleep(msec);
#elif defined(CLOCK_MONOTONIC)
	struct timespec ts;

	ts.tv_sec  = msec / 1000;
	ts.tv_nsec = (msec % 1000) * 1000000;

	// Do this in a loop, so that interrupts don't actually wake us.
	while (ts.tv_sec || ts.tv_nsec) {
		if (nanosleep(&ts, &ts) == 0) {
			break;
		}
	}
#else
	poll(NULL, 0, msec);
#endif
}

struct marriage_notice {
	nng_mtx *mx;
	nng_cv * cv;
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
testutil_marry(nng_socket s1, nng_socket s2)
{
	return (testutil_marry_ex(s1, s2, NULL, NULL, NULL));
}

int
testutil_marry_ex(
    nng_socket s1, nng_socket s2, const char *url, nng_pipe *p1, nng_pipe *p2)
{
	struct marriage_notice note;
	nng_time               timeout;
	int                    rv;
	char                   addr[32];

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
	          s2, NNG_PIPE_EV_ADD_POST, married, &note)) != 0) ||
	    ((rv = nng_listen(s1, url, NULL, 0)) != 0) ||
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

typedef struct {
	uint8_t *   base;
	size_t      rem;
	nng_iov     iov;
	nng_aio *   upper_aio;
	nng_aio *   lower_aio;
	nng_stream *s;
	void (*submit)(nng_stream *, nng_aio *);
} stream_xfr_t;

static void
stream_xfr_free(stream_xfr_t *x)
{
	if (x == NULL) {
		return;
	}
	if (x->upper_aio != NULL) {
		nng_aio_free(x->upper_aio);
	}
	if (x->lower_aio != NULL) {
		nng_aio_free(x->lower_aio);
	}
	nng_free(x, sizeof(*x));
}

static void
stream_xfr_start(stream_xfr_t *x)
{
	nng_iov iov;
	iov.iov_buf = x->base;
	iov.iov_len = x->rem;

	nng_aio_set_iov(x->lower_aio, 1, &iov);
	x->submit(x->s, x->lower_aio);
}

static void
stream_xfr_cb(void *arg)
{
	stream_xfr_t *x = arg;
	int           rv;
	size_t        n;

	rv = nng_aio_result(x->lower_aio);
	if (rv != 0) {
		nng_aio_finish(x->upper_aio, rv);
		return;
	}
	n = nng_aio_count(x->lower_aio);

	x->rem -= n;
	x->base += n;

	if (x->rem == 0) {
		nng_aio_finish(x->upper_aio, 0);
		return;
	}

	stream_xfr_start(x);
}

static stream_xfr_t *
stream_xfr_alloc(nng_stream *s, void (*submit)(nng_stream *, nng_aio *),
    void *buf, size_t size)
{
	stream_xfr_t *x;

	if ((x = nng_alloc(size)) == NULL) {
		return (NULL);
	}
	if (nng_aio_alloc(&x->upper_aio, NULL, NULL) != 0) {
		stream_xfr_free(x);
		return (NULL);
	}
	if (nng_aio_alloc(&x->lower_aio, stream_xfr_cb, x) != 0) {
		stream_xfr_free(x);
		return (NULL);
	}

	// Upper should not take more than 30 seconds, lower not more than 5.
	nng_aio_set_timeout(x->upper_aio, 30000);
	nng_aio_set_timeout(x->lower_aio, 5000);

	nng_aio_begin(x->upper_aio);

	x->s           = s;
	x->rem         = size;
	x->base        = buf;
	x->submit      = submit;

	return (x);
}

static int
stream_xfr_wait(stream_xfr_t *x)
{
	int rv;
	if (x == NULL) {
		return (NNG_ENOMEM);
	}
	nng_aio_wait(x->upper_aio);
	rv = nng_aio_result(x->upper_aio);
	stream_xfr_free(x);
	return (rv);
}

void *
testutil_stream_recv_start(nng_stream *s, void *buf, size_t size)
{
	stream_xfr_t *x;

	x = stream_xfr_alloc(s, nng_stream_recv, buf, size);
	if (x == NULL) {
		return (x);
	}
	stream_xfr_start(x);
	return (x);
}

int
testutil_stream_recv_wait(void *arg)
{
	return (stream_xfr_wait(arg));
}

void *
testutil_stream_send_start(nng_stream *s, void *buf, size_t size)
{
	stream_xfr_t *x;

	x = stream_xfr_alloc(s, nng_stream_send, buf, size);
	if (x == NULL) {
		return (x);
	}
	stream_xfr_start(x);
	return (x);
}

int
testutil_stream_send_wait(void *arg)
{
	return (stream_xfr_wait(arg));
}

// TLS certificates.  These are pre-generated, and should not be used outside
// of these test cases.  They are all using RSA 2048 with SHA256.
// All certs are signed by the root key (making the root self-signed).
// They all expire in about 100 years -- so we don't have to worry about
// expiration.
//
// The server cert uses CN 127.0.0.1.
//
// Country = XX
// State = Utopia
// Locality = Paradise
// Organization = NNG Tests, Inc.
//

const char *testutil_server_key =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEAyPdnRbMrQj9902TGQsmMbG6xTSl9XKbJr55BcnyZifsrqA7B\n"
    "bNSkndVw9Qq+OJQIDBTfRhGdG+o9j3h6SDVvIb62fWtwJ5Fe0eUmeYwPc1PKQzOm\n"
    "MFlMYekXiZsx60yu5LeuUhGlb84+csImH+m3NbutInPJcStSq0WfSV6VNk6DN353\n"
    "5ex66zV2Ms6ikys1vCC434YqIpe1VxUh+IC2widJcLDCxmmJt3TOlx5f9OcKMkxu\n"
    "H4fMAzgjIEpIrUjdb19CGNVvsNrEEB2CShBMgBdqMaAnKFxpKgfzS0JFulxRGNtp\n"
    "srweki+j+a4sJXTv40kELkRQS6uB6wWZNjcPywIDAQABAoIBAQCGSUsot+BgFCzv\n"
    "5JbWafb7Pbwb421xS8HZJ9Zzue6e1McHNVTqc+zLyqQAGX2iMMhvykKnf32L+anJ\n"
    "BKgxOANaeSVYCUKYLfs+JfDfp0druMGexhR2mjT/99FSkfF5WXREQLiq/j+dxiLU\n"
    "bActq+5QaWf3bYddp6VF7O/TBvCNqBfD0+S0o0wtBdvxXItrKPTD5iKr9JfLWdAt\n"
    "YNAk2QgFywFtY5zc2wt4queghF9GHeBzzZCuVj9QvPA4WdVq0mePaPTmvTYQUD0j\n"
    "GT6X5j9JhqCwfh7trb/HfkmLHwwc62zPDFps+Dxao80+vss5b/EYZ4zY3S/K3vpG\n"
    "f/e42S2BAoGBAP51HQYFJGC/wsNtOcX8RtXnRo8eYmyboH6MtBFrZxWl6ERigKCN\n"
    "5Tjni7EI3nwi3ONg0ENPFkoQ8h0bcVFS7iW5kz5te73WaOFtpkU9rmuFDUz37eLP\n"
    "d+JLZ5Kwfn2FM9HoiSAZAHowE0MIlmmIEXSnFtqA2zzorPQLO/4QlR+VAoGBAMov\n"
    "R0yaHg3qPlxmCNyLXKiGaGNzvsvWjYw825uCGmVZfhzDhOiCFMaMb51BS5Uw/gwm\n"
    "zHxmJjoqak8JjxaQ1qKPoeY1TJ5ps1+TRq9Wzm2/zGqJHOXnRPlqwBQ6AFllAMgt\n"
    "Rlp5uqb8QJ+YEo6/1kdGhw9kZWCZEEue6MNQjxnfAoGARLkUkZ+p54di7qz9QX+V\n"
    "EghYgibOpk6R1hviNiIvwSUByhZgbvxjwC6pB7NBg31W8wIevU8K0g4plbrnq/Md\n"
    "5opsPhwLo4XY5albkq/J/7f7k6ISWYN2+WMsIe4Q+42SJUsMXeLiwh1h1mTnWrEp\n"
    "JbxK69CJZbXhoDe4iDGqVNECgYAjlgS3n9ywWE1XmAHxR3osk1OmRYYMfJv3VfLV\n"
    "QSYCNqkyyNsIzXR4qdkvVYHHJZNhcibFsnkB/dsuRCFyOFX+0McPLMxqiXIv3U0w\n"
    "qVe2C28gRTfX40fJmpdqN/c9xMBJe2aJoClRIM8DCBIkG/HMI8a719DcGrS6iqKv\n"
    "VeuKAwKBgEgD+KWW1KtoSjCBlS0NP8HjC/Rq7j99YhKE6b9h2slIa7JTO8RZKCa0\n"
    "qbuomdUeJA3R8h+5CFkEKWqO2/0+dUdLNOjG+CaTFHaUJevzHOzIjpn+VsfCLV13\n"
    "yupGzHG+tGtdrWgLn9Dzdp67cDfSnsSh+KODPECAAFfo+wPvD8DS\n"
    "-----END RSA PRIVATE KEY-----\n";

const char *testutil_server_crt =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDRzCCAi8CFCOIJGs6plMawgBYdDuCRV7UuJuyMA0GCSqGSIb3DQEBCwUAMF8x\n"
    "CzAJBgNVBAYTAlhYMQ8wDQYDVQQIDAZVdG9waWExETAPBgNVBAcMCFBhcmFkaXNl\n"
    "MRgwFgYDVQQKDA9OTkcgVGVzdHMsIEluYy4xEjAQBgNVBAMMCWxvY2FsaG9zdDAg\n"
    "Fw0yMDA1MjMyMzMxMTlaGA8yMTIwMDQyOTIzMzExOVowXzELMAkGA1UEBhMCWFgx\n"
    "DzANBgNVBAgMBlV0b3BpYTERMA8GA1UEBwwIUGFyYWRpc2UxGDAWBgNVBAoMD05O\n"
    "RyBUZXN0cywgSW5jLjESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0B\n"
    "AQEFAAOCAQ8AMIIBCgKCAQEAyPdnRbMrQj9902TGQsmMbG6xTSl9XKbJr55BcnyZ\n"
    "ifsrqA7BbNSkndVw9Qq+OJQIDBTfRhGdG+o9j3h6SDVvIb62fWtwJ5Fe0eUmeYwP\n"
    "c1PKQzOmMFlMYekXiZsx60yu5LeuUhGlb84+csImH+m3NbutInPJcStSq0WfSV6V\n"
    "Nk6DN3535ex66zV2Ms6ikys1vCC434YqIpe1VxUh+IC2widJcLDCxmmJt3TOlx5f\n"
    "9OcKMkxuH4fMAzgjIEpIrUjdb19CGNVvsNrEEB2CShBMgBdqMaAnKFxpKgfzS0JF\n"
    "ulxRGNtpsrweki+j+a4sJXTv40kELkRQS6uB6wWZNjcPywIDAQABMA0GCSqGSIb3\n"
    "DQEBCwUAA4IBAQA86Fqrd4aiih6R3fwiMLwV6IQJv+u5rQeqA4D0xu6v6siP42SJ\n"
    "YMaI2DkNGrWdSFVSHUK/efceCrhnMlW7VM8I1cyl2F/qKMfnT72cxqqquiKtQKdT\n"
    "NDTzv61QMUP9n86HxMzGS7jg0Pknu55BsIRNK6ndDvI3D/K/rzZs4xbqWSSfNfQs\n"
    "fNFBbOuDrkS6/1h3p8SY1uPM18WLVv3GO2T3aeNMHn7YJAKSn+sfaxzAPyPIK3UT\n"
    "W8ecGQSHOqBJJQELyUfMu7lx/FCYKUhN7/1uhU5Qf1pCR8hkIMegtqr64yVBNMOn\n"
    "248fuiHbs9BRknuA/PqjxIDDZTwtDrfVSO/S\n"
    "-----END CERTIFICATE-----\n";

const char *testutil_client_key =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEArohAOr7gv5aNpTEviOPPBJ2fArUX2EajMEtU9tF8H/TTlcMB\n"
    "oy+vYoyNe56jc7CWUfO0S54rg0XaQ7HTI5EWueSR9wrEVK4q+Zg6x1dwr4k5SxD5\n"
    "NcStDXzUjiCi9ygZRxpOUz8jRhKZFENuCdLxSN7E2vuOIU9IR5FpatMlsD33rTOX\n"
    "Pgyx7qNpBj63ZCzY3b09zWBAXc/sLd1mxjlNP/LbtVLrFeIT1j6Gv0UgzxIcEjQ3\n"
    "vybV/EYK7THn7jLhudEa+7fC9jfzwozbuszfEje/U0h0/DF4coGyIQTfDh6Wmk3x\n"
    "5YB2QaI/0jwn8cwracKGtNO+vLqV4yUWZxf5xwIDAQABAoIBADXIEJrJpPIEz6Me\n"
    "0/oH0QwoEg7AhReFNNY18HmaNfiW9fhJPiDuGcpxa0uzp8SHntqkEWPX2qq6BLcl\n"
    "fd2Q4QLpdz08GSHLBb0h9sLko/nDfF8wXMr/zx+/3rPpRK6KsbdiWM54P0NhicBf\n"
    "wvHOCcIdu2WLbNHA35IGMgjUBeIXxAsje63RBS3Dd6RnASxF7bbC/GXiUouQnos1\n"
    "VSLoR6fLQQYlrMOAJU3ruPvMRwkrgaHQ1jl3PL4ilZMuvt7LSAi/KUDKMLRHdLNe\n"
    "tMPITE5CvQ/rBhiUHMsTn1Xb2/jmSuJieJtG2fEDmLFuYZMUFMg1XfQ+ZC9cDCGI\n"
    "wiEYUbkCgYEA1NoKnHp7Zmc2AK1J78uYByEwr8z2nAYZNq5LFeKuCd4rky6v385x\n"
    "IjIYhvPLiGXw/lDfF1T15lHHo2FDAQqDa2rbEe+ycDC7Qa3eJjcsN284n1RM2pl+\n"
    "iNyyhS09YVadelBxWsMqnwdDlf5lrSa7DW1+/u/z2iAw8lGka8XpFpsCgYEA0emd\n"
    "sYqNivonQFEqJxi2kGTBjX8HNEjeF9tTLuAAg0hjhbW4i1v3JsekW9thbG436THa\n"
    "4zWUBmcaEwx0iTD1dqM+d+PbN/4vxoRx9kWQJicfR+sa6eJiwL5UmiqDdX4to5z9\n"
    "MbahemNBzYybr7lcvw+RbL91Fr/z3GooDM9rxkUCgYAuF8mUeTGfy1n2a5BHTV9u\n"
    "q9FPQKNmxitPnA7GfoARwvrMtJ+BZ8M4FIEbOFArCWhWqkylUNCvP6ZryvQnlY9A\n"
    "A7PM/os1oFfssSoaPHhmyL8KQcciz3qHSMOf81wHaCpSAnmJnhnstjX8lUqPZIO9\n"
    "NKj7rBqycaYn02Y3sHP5YQKBgQDQxOQNW5uCiWDYWuDtmWqZGVxW+euUWJRqbbvB\n"
    "dw+LgkdZCG7OS1z3uL8CjKHMUaJRzz+/kd3ysEACifStLYAzyg+q9XdlrOyfJ8Kg\n"
    "CHdhOq+lu3I9Aubsg19pJLcx95g0jUJUWysmqekcIagFkPlpHHaqDZDKW4aRxRKo\n"
    "CvNJcQKBgA9DB8OzHA/gp8TztxUZu8hAVfehLxVORquFvMRF0cr8uxjbu/6sDhzc\n"
    "TRUkXRUe4DGxxMzAd+1SF/IWlcuZlfcuZrytH1hbjmrN8H30y+yGXFsSGCI/rudk\n"
    "rLXNS+vWEeuOV8lQuQY0fkokmxnmhkPDMXra5/3KrVMzm3ZNF5N8\n"
    "-----END RSA PRIVATE KEY-----\n";

const char *testutil_client_crt =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDdzCCAl8CFEzqJgxMn+OTdw7RjLtz8FlhrQ0HMA0GCSqGSIb3DQEBCwUAMHcx\n"
    "CzAJBgNVBAYTAlhYMQ8wDQYDVQQIDAZVdG9waWExETAPBgNVBAcMCFBhcmFkaXNl\n"
    "MRgwFgYDVQQKDA9OTkcgVGVzdHMsIEluYy4xFDASBgNVBAsMC0NsaWVudCBDZXJ0\n"
    "MRQwEgYDVQQDDAtUZXN0IENsaWVudDAgFw0yMDA1MjMxODQ1MjZaGA8yMTIwMDQy\n"
    "OTE4NDUyNlowdzELMAkGA1UEBhMCWFgxDzANBgNVBAgMBlV0b3BpYTERMA8GA1UE\n"
    "BwwIUGFyYWRpc2UxGDAWBgNVBAoMD05ORyBUZXN0cywgSW5jLjEUMBIGA1UECwwL\n"
    "Q2xpZW50IENlcnQxFDASBgNVBAMMC1Rlc3QgQ2xpZW50MIIBIjANBgkqhkiG9w0B\n"
    "AQEFAAOCAQ8AMIIBCgKCAQEAoHWEJXvfaHDM33AyYbJHggKOllgcvwscEnsXztIt\n"
    "OK+0jO6SRFSbtye1cjtrkGVCYBjeWMcOdEiNB0pw3PceVpF/Q9ifCuaSYsJA3sPH\n"
    "wi/A3G7ZTe2KCH1i26I4zyw1Bn5AzkaDDXsaht2S9PEqIBCbWo/V1pWiv4QdYmLT\n"
    "/UFYJDxFpFC3iKVC+BDv9yzziyaFXOYsQJXcaq8ZRD79bNV5NFfzUih8RoasIdD4\n"
    "LoamBSbbr5XzstTISus+wu1JDKgKkYMJhLGA/tdU/eOKuTDx89yO4ba23W74xeqW\n"
    "JYe0wPy+krmeB5M7UA7jIvg1JXhYACxujhieMp7wcC3FPwIDAQABMA0GCSqGSIb3\n"
    "DQEBCwUAA4IBAQCMTQ89YnD19bCGIdUl/z6w2yx1x1kvTYHT+SzhUprsgiuS3KT1\n"
    "RZNhjf5U3Yu+B6SrJCLuylv+L2zQfmHogp3lV7bayOA7r/rVy5fdmHS+Ei1w6LDL\n"
    "t8jayiRMPG4VCgaG486yI73PFpK5DXnyFqSd23TlWvNoNeVag5gjlhzG+mHZBSB2\n"
    "ExpGY3SPxrKSzDqIITVPVgzjW25N8qtgLXC6HODDiViNYq1nmuoS4O80NIYAPPs6\n"
    "sxUMa5kT+zc17q57ZcgNq/sSGI3BU4b/E/8ntIwiui2xWSf/4JR6xtanih8uY5Pu\n"
    "QTgg9qTtFgtu4WWUP7JhreoINTw6O4/g5Z18\n"
    "-----END CERTIFICATE-----\n";
