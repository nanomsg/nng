//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
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

//
// Debugging Support
//

// nni_plat_abort crashes the system; it should do whatever is appropriate
// for abnormal programs on the platform, such as calling abort().
extern void nni_plat_abort(void);

// nni_plat_println is used to emit debug messages.  Typically this is used
// during core debugging, or to emit panic messages.  Message content will
// not contain newlines, but the output will add them.
extern void nni_plat_println(const char *);

// nni_plat_strerror allows the platform to use additional error messages
// for additional error codes.  The err code passed in should be the
// equivalent of errno or GetLastError, without the NNG_ESYSERR component.
// The platform should make sure that the returned value will be valid
// after the call returns.  (If necessary, thread-local storage can be
// used.)
extern const char *nni_plat_strerror(int);

//
// Memory Management
//

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

typedef struct nni_plat_mtx nni_plat_mtx;
typedef struct nni_plat_cv  nni_plat_cv;
typedef struct nni_plat_thr nni_plat_thr;

//
// Threading & Synchronization Support
//

// nni_plat_mtx_init initializes a mutex structure.  An initialized mutex must
// be distinguishable from zeroed memory.
extern void nni_plat_mtx_init(nni_plat_mtx *);

// nni_plat_mtx_fini destroys the mutex and releases any resources allocated
// for it's use.  If the mutex is zeroed memory, this should do nothing.
extern void nni_plat_mtx_fini(nni_plat_mtx *);

// nni_plat_mtx_lock locks the mutex.  This is not recursive -- a mutex can
// only be entered once.
extern void nni_plat_mtx_lock(nni_plat_mtx *);

// nni_plat_mtx_unlock unlocks the mutex.  This can only be performed by the
// thread that owned the mutex.
extern void nni_plat_mtx_unlock(nni_plat_mtx *);

// nni_plat_cv_init initializes a condition variable.  We require a mutex be
// supplied with it, and that mutex must always be held when performing any
// operations on the condition variable (other than fini.)  As with mutexes, an
// initialized mutex should be distinguishable from zeroed memory.
extern void nni_plat_cv_init(nni_plat_cv *, nni_plat_mtx *);

// nni_plat_cv_fini releases all resources associated with condition variable.
// If the cv points to just zeroed memory (was never initialized), it does
// nothing.
extern void nni_plat_cv_fini(nni_plat_cv *);

// nni_plat_cv_wake wakes all waiters on the condition.  This should be
// called with the lock held.
extern void nni_plat_cv_wake(nni_plat_cv *);

// nni_plat_cv_wake1 wakes only a single waiter.  Use with caution
// to avoid losing the wakeup when multiple waiters may be present.
extern void nni_plat_cv_wake1(nni_plat_cv *);

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

//
// Clock Support
//

// nn_plat_clock returns a number of milliseconds since some arbitrary time
// in the past.  The values returned by nni_clock must use the same base
// as the times used in nni_plat_cond_waituntil.  The nni_plat_clock() must
// return values > 0, and must return values smaller than 2^63.  (We could
// relax this last constraint, but there is no reason to, and leaves us the
// option of using negative values for other purposes in the future.)
extern nni_time nni_plat_clock(void);

// nni_plat_sleep sleeps for the specified number of milliseconds (at least).
extern void nni_plat_sleep(nni_duration);

//
// Entropy Support
//

// nni_plat_seed_prng seeds the PRNG subsystem.  The specified number
// of bytes of entropy should be stashed.  When possible, cryptographic
// quality entropy sources should be used.  Note that today we prefer
// to seed up to 256 bytes of data.
extern void nni_plat_seed_prng(void *, size_t);

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

//
// TCP Support.
//

typedef struct nni_plat_tcp_ep   nni_plat_tcp_ep;
typedef struct nni_plat_tcp_pipe nni_plat_tcp_pipe;

// nni_plat_tcp_ep_init creates a new endpoint associated with the local
// and remote addresses.
extern int nni_plat_tcp_ep_init(
    nni_plat_tcp_ep **, const nni_sockaddr *, const nni_sockaddr *, int);

// nni_plat_tcp_ep_fini closes the endpoint and releases resources.
extern void nni_plat_tcp_ep_fini(nni_plat_tcp_ep *);

// nni_plat_tcp_ep_close closes the endpoint; this might not close the
// actual underlying socket, but it should call shutdown on it.
// Further operations on the pipe should return NNG_ECLOSED.
extern void nni_plat_tcp_ep_close(nni_plat_tcp_ep *);

// nni_plat_tcp_listen creates an TCP socket in listening mode, bound
// to the specified path.
extern int nni_plat_tcp_ep_listen(nni_plat_tcp_ep *, nni_sockaddr *);

// nni_plat_tcp_ep_accept starts an accept to receive an incoming connection.
// An accepted connection will be passed back in the a_pipe member.
extern void nni_plat_tcp_ep_accept(nni_plat_tcp_ep *, nni_aio *);

// nni_plat_tcp_connect is the client side.
// An accepted connection will be passed back in the a_pipe member.
extern void nni_plat_tcp_ep_connect(nni_plat_tcp_ep *, nni_aio *);

// nni_plat_tcp_pipe_fini closes the pipe, and releases all resources
// associated with it.
extern void nni_plat_tcp_pipe_fini(nni_plat_tcp_pipe *);

// nni_plat_tcp_pipe_close closes the socket, or at least shuts it down.
// Further operations on the pipe should return NNG_ECLOSED.
extern void nni_plat_tcp_pipe_close(nni_plat_tcp_pipe *);

// nni_plat_tcp_pipe_send sends data in the iov buffers to the peer.
// The platform may modify the iovs.
extern void nni_plat_tcp_pipe_send(nni_plat_tcp_pipe *, nni_aio *);

// nni_plat_tcp_pipe_recv receives data into the buffers provided by the
// I/O vector (iovs).  The platform should attempt to scatter the received
// data into the iovs if possible.
//
// It is an error for the caller to supply any IO vector elements with
// zero length.
//
// It is possible for the TCP reader to return less data than is requested,
// in which case the caller is responsible for resubmitting.  The platform
// should not return "zero" data however.  (It is an error to attempt to
// receive zero bytes.)  The platform may not modify the I/O vector.
extern void nni_plat_tcp_pipe_recv(nni_plat_tcp_pipe *, nni_aio *);

// nni_plat_tcp_pipe_peername gets the peer name.
extern int nni_plat_tcp_pipe_peername(nni_plat_tcp_pipe *, nni_sockaddr *);

// nni_plat_tcp_pipe_sockname gets the local name.
extern int nni_plat_tcp_pipe_sockname(nni_plat_tcp_pipe *, nni_sockaddr *);

// nni_plat_tcp_pipe_set_nodelay sets nodelay, disabling Nagle, according
// to the parameter.  true disables Nagle; false enables Nagle.
extern int nni_plat_tcp_pipe_set_nodelay(nni_plat_tcp_pipe *, bool);

// nni_plat_tcp_pipe_set_keepalive indicates that the TCP pipe should send
// keepalive probes.  Tuning of these keepalives is current unsupported.
extern int nni_plat_tcp_pipe_set_keepalive(nni_plat_tcp_pipe *, bool);

// nni_plat_tcp_ntop obtains the IP address for the socket (enclosing it
// in brackets if it is IPv6) and port.  Enough space for both must
// be present (48 bytes and 6 bytes each), although if either is NULL then
// those components are skipped.
extern int nni_plat_tcp_ntop(const nni_sockaddr *, char *, char *);

// nni_plat_tcp_resolv resolves a TCP name asynchronously.  The family
// should be one of NNG_AF_INET, NNG_AF_INET6, or NNG_AF_UNSPEC.  The
// first two constrain the name to those families, while the third will
// return names of either family.  The passive flag indicates that the
// name will be used for bind(), otherwise the name will be used with
// connect().  The host part may be NULL only if passive is true.
extern void nni_plat_tcp_resolv(
    const char *, const char *, int, int, nni_aio *);

// nni_plat_udp_resolve is just like nni_plat_tcp_resolve, but looks up
// service names using UDP.
extern void nni_plat_udp_resolv(
    const char *, const char *, int, int, nni_aio *);

//
// IPC (UNIX Domain Sockets & Named Pipes) Support.
//

typedef struct nni_plat_ipc_ep   nni_plat_ipc_ep;
typedef struct nni_plat_ipc_pipe nni_plat_ipc_pipe;

// nni_plat_ipc_ep_init creates a new endpoint associated with the url.
// The final field is the mode, either for dialing (NNI_EP_MODE_DIAL) or
// listening (NNI_EP_MODE_LISTEN).
extern int nni_plat_ipc_ep_init(nni_plat_ipc_ep **, const nni_sockaddr *, int);

// nni_plat_ipc_ep_fini closes the endpoint and releases resources.
extern void nni_plat_ipc_ep_fini(nni_plat_ipc_ep *);

// nni_plat_ipc_ep_close closes the endpoint; this might not close the
// actual underlying socket, but it should call shutdown on it.
// Further operations on the pipe should return NNG_ECLOSED.
extern void nni_plat_ipc_ep_close(nni_plat_ipc_ep *);

// nni_plat_tcp_listen creates an IPC socket in listening mode, bound
// to the specified path.
extern int nni_plat_ipc_ep_listen(nni_plat_ipc_ep *);

// nni_plat_ipc_ep_accept starts an accept to receive an incoming connection.
// An accepted connection will be passed back in the a_pipe member.
extern void nni_plat_ipc_ep_accept(nni_plat_ipc_ep *, nni_aio *);

// nni_plat_ipc_connect is the client side.
// An accepted connection will be passed back in the a_pipe member.
extern void nni_plat_ipc_ep_connect(nni_plat_ipc_ep *, nni_aio *);

// nni_plat_ipc_ep_set_security_descriptor sets the Windows security
// descriptor. This is *only* supported for Windows platforms.  All
// others return NNG_ENOTSUP.  The void argument is a pointer to
// a SECURITY_DESCRIPTOR object, and must be valid.
extern int nni_plat_ipc_ep_set_security_descriptor(nni_plat_ipc_ep *, void *);

// nni_plat_ipc_ep_set_permissions sets UNIX style permissions
// on the named pipes.  This basically just does a chmod() on the
// named pipe, and is only supported o the server side, and only on
// systems that support this (POSIX, not Windows).  Note that changing
// ownership is not supported at this time.  Most systems use only
// 16-bits, the lower 12 of which are user, group, and other, e.g.
// 0640 gives read/write access to user, read to group, and prevents
// any other user from accessing it.  This option only has meaning
// for listeners, on dialers it is ignored.
extern int nni_plat_ipc_ep_set_permissions(nni_plat_ipc_ep *, uint32_t);

// nni_plat_ipc_pipe_fini closes the pipe, and releases all resources
// associated with it.
extern void nni_plat_ipc_pipe_fini(nni_plat_ipc_pipe *);

// nni_plat_ipc_pipe_close closes the socket, or at least shuts it down.
// Further operations on the pipe should return NNG_ECLOSED.
extern void nni_plat_ipc_pipe_close(nni_plat_ipc_pipe *);

// nni_plat_ipc_pipe_send sends data in the iov buffers to the peer.
// The platform may modify the iovs.
extern void nni_plat_ipc_pipe_send(nni_plat_ipc_pipe *, nni_aio *);

// nni_plat_ipc_pipe_recv recvs data into the buffers provided by the iovs.
// The platform may modify the iovs.
extern void nni_plat_ipc_pipe_recv(nni_plat_ipc_pipe *, nni_aio *);

// nni_plat_ipc_pipe_get_peer_uid obtains the peer user id, if possible.
// NB: Only POSIX systems support user IDs.
extern int nni_plat_ipc_pipe_get_peer_uid(nni_plat_ipc_pipe *, uint64_t *);

// nni_plat_ipc_pipe_get_peer_gid obtains the peer group id, if possible.
// NB: Only POSIX systems support group IDs.
extern int nni_plat_ipc_pipe_get_peer_gid(nni_plat_ipc_pipe *, uint64_t *);

// nni_plat_ipc_pipe_get_peer_pid obtains the peer process id, if possible.
extern int nni_plat_ipc_pipe_get_peer_pid(nni_plat_ipc_pipe *, uint64_t *);

// nni_plat_ipc_pipe_get_peer_zoneid obtains the peer zone id, if possible.
// NB: Only illumos & SunOS systems have the notion of "zones".
extern int nni_plat_ipc_pipe_get_peer_zoneid(nni_plat_ipc_pipe *, uint64_t *);

//
// UDP support. UDP is not connection oriented, and only has the notion
// of being bound, sendto, and recvfrom.  (It is possible to set up a
// connect call that semantically acts as a filter on recvfrom, but we
// don't use that.)  Outbound packets will include the destination address
// in the AIO, and inbound packets include the source address in the AIO.
// For now we don't have more sophisticated options like setting the TTL.
//
typedef struct nni_plat_udp nni_plat_udp;

// nni_plat_udp_open initializes a UDP socket, binding to the local
// address specified specified in the AIO.  The remote address is
// not used.  The resulting nni_plat_udp structure is returned in the
// the aio's a_pipe.
extern int nni_plat_udp_open(nni_plat_udp **, nni_sockaddr *);

// nni_plat_udp_close closes the underlying UDP socket.
extern void nni_plat_udp_close(nni_plat_udp *);

// nni_plat_udp_send sends the data in the aio to the the
// destination specified in the nni_aio.  The iovs are the
// UDP payload.
extern void nni_plat_udp_send(nni_plat_udp *, nni_aio *);

// nni_plat_udp_pipe_recv recvs a message, storing it in the iovs
// from the UDP payload.  If the UDP payload will not fit, then
// NNG_EMSGSIZE results.
extern void nni_plat_udp_recv(nni_plat_udp *, nni_aio *);

//
// Notification Pipe Pairs
//

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

extern int nni_plat_udp_sockname(nni_plat_udp *, nni_sockaddr *);

//
// File/Store Support
//
// Some transports require a persistent storage for things like
// key material, etc.  Generally, these are all going to be relatively
// small objects (such as certificates), so we only require a synchronous
// implementation from platforms.  This Key-Value API is intended to
// to support using the Key's as filenames, and keys will consist of
// only these characters: [0-9a-zA-Z._-].  The directory used should be
// determined by using an environment variable (NNG_STATE_DIR), or
// using some other application-specific method.
//
// We also support listing keys, for the case where a key must be looked
// up -- for example to get a list of certificates, or some such.
//

// nni_plat_file_put writes the named file, with the provided data,
// and the given size.  If the file already exists it is overwritten.
// The permissions on the file should be limited to read and write
// access by the entity running the application only.
extern int nni_plat_file_put(const char *, const void *, size_t);

// nni_plat_file_get reads the entire named file, allocating storage
// to receive the data and returning the data and the size in the
// reference arguments.  The data pointer should be freed with nni_free
// using the supplied size when no longer needed.
extern int nni_plat_file_get(const char *, void **, size_t *);

// nni_plat_file_delete deletes the named file.  If the name refers to
// a directory, then that will be removed only if empty.
extern int nni_plat_file_delete(const char *);

// nni_plat_file_check checks the file path to determine its type.
// If the path does not exist, then NNG_ENOENT is returned.
enum nni_plat_file_type_val {
	NNI_PLAT_FILE_TYPE_FILE,  // normal file
	NNI_PLAT_FILE_TYPE_DIR,   // normal directory
	NNI_PLAT_FILE_TYPE_OTHER, // something else (pipe, device node, etc.)
};
extern int nni_plat_file_type(const char *, int *);

enum nni_plat_file_walk_result {
	NNI_PLAT_FILE_WALK_CONTINUE,
	NNI_PLAT_FILE_WALK_STOP,        // stop walking (all done)
	NNI_PLAT_FILE_WALK_PRUNE_SIB,   // skip siblings and their children
	NNI_PLAT_FILE_WALK_PRUNE_CHILD, // skip children
};

enum nni_plat_file_walk_flags {
	NNI_PLAT_FILE_WALK_DEPTH_FIRST   = 0, // get children first
	NNI_PLAT_FILE_WALK_BREADTH_FIRST = 1, // get siblings first (later)
	NNI_PLAT_FILE_WALK_SHALLOW = 2, // do not descend into subdirectories
	NNI_PLAT_FILE_WALK_FILES_ONLY = 4, // directory names are not reported
};

// nni_plat_file_walker is called for each pathname found by walking a
// directory tree.  It returns one of the nni_plat_file_walk_result values.
typedef int (*nni_plat_file_walker)(const char *, void *);

// nni_plat_file_walk walks a directory tree, calling the walker function
// with the path name, and the supplied void * argument.
extern int nni_plat_file_walk(const char *, nni_plat_file_walker, void *, int);

typedef struct nni_plat_flock nni_plat_flock;

// nni_plat_file_lock locks the file.  This usually means open it (creating
// if it does not exist) and doing a lock operation.  The nni_plat_flock
// is our handle for the lock, to unlock.  Usually its just a file descriptor,
// and we can unlock by doing close().  Note that this is a "try-lock"
// operation -- if the file is already locked then NNG_EBUSY is returned.
extern int nni_plat_file_lock(const char *path, nni_plat_flock *);

// nni_plat_file_unlock unlocks the previously locked file.
extern void nni_plat_file_unlock(nni_plat_flock *);

// nni_plat_dir_open attempts to "open a directory" for listing.  The
// handle for further operations is returned in the first argument, and
// the directory name is supplied in the second.
extern int nni_plat_dir_open(void **, const char *);

// nni_plat_dir_next gets the next directory entry.  Each call returns
// a new entry (arbitrary order).  When no more entries exist, it returns
// NNG_ENOENT.  The returned name is valid until the next call to this
// function, or until the directory is closed.  Only files are returned,
// subdirectories are not reported.
extern int nni_plat_dir_next(void *, const char **);

// nni_plat_dir_close closes the directory handle, freeing all
// resources associated with it.
extern void nni_plat_dir_close(void *);

// nni_plat_dir_create creates a directory.  Any parent directories must
// already exist.  If the directory already exists, 0 is returned.
extern int nni_plat_dir_create(const char *);

// nni_plat_dir_remove removes a directory, which must already be empty.
// If it does not exist, 0 is returned.
extern int nni_plat_dir_remove(const char *);

// nni_plat_temp_dir returns a temporary/scratch directory for the platform
// The result should be freed with nni_strfree().
extern char *nni_plat_temp_dir(void);

// nni_plat_home_dir returns the "home" directory for the user running the
// application.  This is a convenient place to store preferences, etc.
// Applications should append an application specific directory name.
// The result should be freed with nni_strfree().
extern char *nni_plat_home_dir(void);

// nni_plat_join_dir joins to path components to make a path name.
// For example. on UNIX systems nni_plat_join_dir("/tmp", "a") returns
// "/tmp/a".  The pathname returned should be freed with nni_strfree().
extern char *nni_plat_join_dir(const char *, const char *);

// nni_plat_file_basename returns the "file" part of the file name.
// The returned pointer will usually reference the end of the supplied
// string, and may not be altered.
extern const char *nni_plat_file_basename(const char *);

//
// Actual platforms we support.  This is included up front so that we can
// get the specific types that are supplied by the platform.
#if defined(NNG_PLATFORM_POSIX)
#include "platform/posix/posix_impl.h"
#elif defined(NNG_PLATFORM_WINDOWS)
#include "platform/windows/win_impl.h"
#else
#error "unknown platform"
#endif

#endif // CORE_PLATFORM_H
