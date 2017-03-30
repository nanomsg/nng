//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_PLATFORM_H
#define CORE_PLATFORM_H

// We require some standard C header files.  The only one of these that might
// be problematic is <stdint.h>, which is required for C99.  Older versions
// of the Windows compilers might not have this.  However, latest versions of
// MS Studio have a functional <stdint.h>.  If this impacts you, just upgrade
// your tool chain.
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

// These are the APIs that a platform must implement to support nng.

// A word about fork-safety: This library is *NOT* fork safe, in that
// functions may not be called in the child process without an intervening
// exec().  The library attempts to detect this situation, and crashes the
// process with an error message if it encounters it.  (See nn_platform_init
// below.)
//
// Additionally, some file descriptors may leak across fork even to
// child processes.  We make every reasonable effort to ensure that this
// does not occur, but on some platforms there are unavoidable race
// conditions between file creation and marking the file close-on-exec.
//
// Forkers should use posix_spawn() if possible, and as much as possible
// arrange for file close on exec by posix_spawn, or close the descriptors
// they do not need in the child.  (Note that posix_spawn() does *NOT*
// arrange for pthread_atfork() handlers to be called on some platforms.)

// nni_plat_abort crashes the system; it should do whatever is appropriate
// for abnormal programs on the platform, such as calling abort().
extern void nni_plat_abort(void);

// nni_plat_println is used to emit debug messages.  Typically this is used
// during core debugging, or to emit panic messages.  Message content will
// not contain newlines, but the output will add them.
extern void nni_plat_println(const char *);

// nni_alloc allocates memory.  In most cases this can just be malloc().
// However, you may provide a different allocator, for example it is
// possible to use a slab allocator or somesuch.  It is permissible for this
// to return NULL if memory cannot be allocated.
extern void *nni_alloc(size_t);

// nni_free frees memory allocated with nni_alloc. It takes a size because
// some allocators do not track size, or can operate more efficiently if
// the size is provided with the free call.  Examples of this are slab
// allocators like this found in Solaris/illumos (see libumem or kmem).
// This routine does nothing if supplied with a NULL pointer and zero size.
// Most implementations can just call free() here.
extern void nni_free(void *, size_t);

typedef struct nni_plat_mtx		nni_plat_mtx;
typedef struct nni_plat_cv		nni_plat_cv;
typedef struct nni_plat_thr		nni_plat_thr;
typedef struct nni_plat_tcpsock		nni_plat_tcpsock;
typedef struct nni_plat_ipcsock		nni_plat_ipcsock;

// Mutex handling.

// nni_plat_mtx_init initializes a mutex structure.  This may require dynamic
// allocation, depending on the platform.  It can return NNG_ENOMEM if that
// fails.  An initialized mutex must be distinguishable from zeroed memory.
extern int nni_plat_mtx_init(nni_plat_mtx *);

// nni_plat_mtx_fini destroys the mutex and releases any resources allocated
// for it's use.  If the mutex is zeroed memory, this should do nothing.
extern void nni_plat_mtx_fini(nni_plat_mtx *);

// nni_plat_mtx_lock locks the mutex.  This is not recursive -- a mutex can
// only be entered once.
extern void nni_plat_mtx_lock(nni_plat_mtx *);

// nni_plat_mtx_unlock unlocks the mutex.  This can only be performed by the
// threadthat owned the mutex.
extern void nni_plat_mtx_unlock(nni_plat_mtx *);

// nni_plat_mtx_tryenter tries to lock the mutex.  If it can't, it may return
// NNG_EBUSY if the mutex is already owned.
extern int nni_plat_mtx_trylock(nni_plat_mtx *);

// nni_plat_cv_init initializes a condition variable.  We require a mutex be
// supplied with it, and that mutex must always be held when performing any
// operations on the condition variable (other than fini.)  This may require
// dynamic allocation, and if so this operation may fail with NNG_ENOMEM.
// As with mutexes, an initialized mutex should be distinguishable from
// zeroed memory.
extern int nni_plat_cv_init(nni_plat_cv *, nni_plat_mtx *);

// nni_plat_cv_fini releases all resources associated with condition variable.
// If the cv points to just zeroed memory (was never initialized), it does
// nothing.
extern void nni_plat_cv_fini(nni_plat_cv *);

// nni_plat_cv_wake wakes all waiters on the condition.  This should be
// called with the lock held.
extern void nni_plat_cv_wake(nni_plat_cv *);

// nni_plat_cv_wait waits for a wake up on the condition variable.  The
// associated lock is atomically released and reacquired upon wake up.
// Callers can be spuriously woken.  The associated lock must be held.
extern void nni_plat_cv_wait(nni_plat_cv *);

// nni_plat_cv_until waits for a wakeup on the condition variable, or
// until the system time reaches the specified absolute time.  (It is an
// absolute form of nni_cond_timedwait.)  Early wakeups are possible, so
// check the condition.  It will return either NNG_ETIMEDOUT, or 0.
extern int nni_plat_cv_until(nni_plat_cv *, nni_time);

// nni_plat_thr_init creates a thread that runs the given function. The
// thread receives a single argument.  The thread starts execution
// immediately.
extern int nni_plat_thr_init(nni_plat_thr *, void (*)(void *), void *);

// nni_thread_reap waits for the thread to exit, and then releases any
// resources associated with the thread.  After this returns, it
// is an error to reference the thread in any further way.
extern void nni_plat_thr_fini(nni_plat_thr *);

// nn_plat_clock returns a number of microseconds since some arbitrary time
// in the past.  The values returned by nni_clock must use the same base
// as the times used in nni_plat_cond_waituntil.  The nni_plat_clock() must
// returnvalues > 0, and must return values smaller than 2^63.  (We could relax
// this last constraint, but there is no reason to, and leaves us the option
// of using negative values for other purposes in the future.)
extern nni_time nni_plat_clock(void);

// nni_plat_usleep sleeps for the specified number of microseconds (at least).
extern void nni_plat_usleep(nni_duration);

// nni_plat_init is called to allow the platform the chance to
// do any necessary initialization.  This routine MUST be idempotent,
// and threadsafe, and will be called before any other API calls, and
// may be called at any point thereafter.  It is permitted to return
// an error if some critical failure inializing the platform occurs,
// but once this succeeds, all future calls must succeed as well, unless
// nni_plat_fini has been called.
//
// The function argument should be called if the platform has not initialized
// (i.e. exactly once), and its result passed back to the caller.  If it
// does not return 0 (success), then it may be called again to try to
// initialize the platform again at a later date.
extern int nni_plat_init(int (*)(void));

// nni_plat_fini is called to clean up resources.  It is intended to
// be called as the last thing executed in the library, and no other functions
// will be called until nni_platform_init is called.
extern void nni_plat_fini(void);

// nni_plat_strerror allows the platform to use additional error messages
// for additional error codes.  The err code passed in should be the
// equivalent of errno or GetLastError, without the NNG_ESYSERR component.
// The platform should make sure that the returned value will be valid
// after the call returns.  (If necessary, thread-local storage can be
// used.)
extern const char *nni_plat_strerror(int);

// nni_plat_lookup_host looks up a hostname in DNS, or the local hosts
// file, or whatever.  If your platform lacks support for naming, it must
// at least cope with converting IP addresses in string form.  The final
// flags may include NNI_FLAG_IPV4ONLY to prevent IPv6 names from being
// returned on dual stack machines.
extern int nni_plat_lookup_host(const char *, nni_sockaddr *, int);

// nni_plat_tcp_init initializes the socket, for example it can
// set underlying file descriptors to -1, etc.
extern int nni_plat_tcp_init(nni_plat_tcpsock **);

// nni_plat_tcp_fini just closes a TCP socket, and releases any related
// resources.
extern void nni_plat_tcp_fini(nni_plat_tcpsock *);

// nni_plat_tcp_shutdown performs a shutdown of the socket.  For
// BSD sockets, this closes both sides of the TCP connection gracefully,
// but the underlying file descriptor is left open.  (This part is critical
// to prevention of close() related races.)
extern void nni_plat_tcp_shutdown(nni_plat_tcpsock *);

// nni_plat_tcp_listen creates a TCP socket in listening mode, bound
// to the specified address.  Note that nni_plat_tcpsock should be defined
// to whatever your platform uses.  For most systems its just "int".
extern int nni_plat_tcp_listen(nni_plat_tcpsock *, const nni_sockaddr *);

// nni_plat_tcp_accept does the accept to accept an inbound connection.
// The tcpsock used for the server will have been set up with the
// nni_plat_tcp_listen.
extern int nni_plat_tcp_accept(nni_plat_tcpsock *, nni_plat_tcpsock *);

// nni_plat_tcp_connect is the client side.  Two addresses are supplied,
// as the client may specify a local address to which to bind.  This
// second address may be NULL to use ephemeral ports, which is the
// usual default.
extern int nni_plat_tcp_connect(nni_plat_tcpsock *, const nni_sockaddr *,
    const nni_sockaddr *);

// nni_plat_tcp_aio_send sends the data to the remote side asynchronously.
// The data to send is stored in the a_iov field of the aio, and the array
// of iovs will never be larger than 4.  The platform may modify the iovs,
// or the iov list.
extern int nni_plat_tcp_aio_send(nni_plat_tcpsock *, nni_aio *);

// nni_plat_tcp_aio_recv recvs data into the buffers provided by the
// iovs.  The implementation does not return until the iovs are completely
// full, or an error condition occurs.
extern int nni_plat_tcp_aio_recv(nni_plat_tcpsock *, nni_aio *);

// nni_plat_ipc_init initializes the socket, for example it can
// set underlying file descriptors to -1, etc.
extern int nni_plat_ipc_init(nni_plat_ipcsock **);

// nni_plat_ipc_fini just closes an IPC socket, and releases any related
// resources.
extern void nni_plat_ipc_fini(nni_plat_ipcsock *);

// nni_plat_ipc_shutdown performs a shutdown of the socket.  For
// BSD sockets, this closes both sides of the IPC connection gracefully,
// but the underlying file descriptor is left open.  (This part is critical
// to prevention of close() related races.)
extern void nni_plat_ipc_shutdown(nni_plat_ipcsock *);

// nni_plat_tcp_listen creates an IPC socket in listening mode, bound
// to the specified path.  Note that nni_plat_ipcsock should be defined
// to whatever your platform uses.  For most systems its just "int".
extern int nni_plat_ipc_listen(nni_plat_ipcsock *, const char *);

// nni_plat_ipc_accept does the accept to accept an inbound connection.
// The ipcsock used for the server will have been set up with the
// nni_plat_ipc_listen.
extern int nni_plat_ipc_accept(nni_plat_ipcsock *, nni_plat_ipcsock *);

// nni_plat_ipc_connect is the client side.
extern int nni_plat_ipc_connect(nni_plat_ipcsock *, const char *);

// nni_plat_ipc_aio_send sends data to the peer.  The platform is responsible
// for attempting to send all of the data.  The iov count will never be
// larger than 4.  The platform may modify the iovs.
extern int nni_plat_ipc_aio_send(nni_plat_ipcsock *, nni_aio *);

// nni_plat_ipc_aio_recv recvs data into the buffers provided by the
// iovs.  The implementation does not return until the iovs are completely
// full, or an error condition occurs.
extern int nni_plat_ipc_aio_recv(nni_plat_ipcsock *, nni_aio *);

// nni_plat_seed_prng seeds the PRNG subsystem.  The specified number
// of bytes of entropy should be stashed.  When possible, cryptographic
// quality entropy sources should be used.  Note that today we prefer
// to seed up to 256 bytes of data.
extern void nni_plat_seed_prng(void *, size_t);

// nni_plat_pipe creates a pair of linked file descriptors that are
// suitable for notification via SENDFD/RECVFD.  These are platform
// specific and exposed to applications for integration into event loops.
// The first pipe is written to by nng to notify, and the second pipe is
// generally read from to clear the event.   The implementation is not
// obliged to provide two pipes -- for example eventfd can be used with
// just a single file descriptor.  In such a case the implementation may
// just provide the same value twice.
extern int nni_plat_pipe_open(int *, int *);

// nni_plat_pipe_raise pushes a notification to the pipe.  Usually this
// will just be a non-blocking attempt to write a single byte.  It may
// however use any other underlying system call that is appropriate.
extern void nni_plat_pipe_raise(int);

// nni_plat_pipe_clear clears all notifications from the pipe.  Usually this
// will just be a non-blocking read.  (The call should attempt to read
// all data on a pipe, for example.)
extern void nni_plat_pipe_clear(int);

// nni_plat_pipe_close closes both pipes that were provided by the open
// routine.
extern void nni_plat_pipe_close(int, int);

// XXX: Stuff to REMOVE
extern int nni_plat_tcp_send(nni_plat_tcpsock *, nni_iov *, int);
extern int nni_plat_tcp_recv(nni_plat_tcpsock *, nni_iov *, int);
extern int nni_plat_ipc_send(nni_plat_ipcsock *, nni_iov *, int);
extern int nni_plat_ipc_recv(nni_plat_ipcsock *, nni_iov *, int);

// Actual platforms we support.  This is included up front so that we can
// get the specific types that are supplied by the platform.
#if defined(PLATFORM_POSIX)
#include "platform/posix/posix_impl.h"
#elif defined(PLATFORM_WINDOWS)
#include "platform/windows/win_impl.h"
#else
#error "unknown platform"
#endif

#endif // CORE_PLATFORM_H
