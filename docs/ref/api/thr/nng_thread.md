# nng_thread

## NAME

nng_thread --- thread of execution

## SYNOPSIS

```c
#include <nng/nng.h>

typedef struct nng_thread nng_thread;

int nng_thread_create(nng_thread **thrp, void (*func)(void *), void *arg);
void nng_thread_destroy(nng_thread *thr);
void nng_thread_set_name(nng_thread *thr, const char *name);
```

### DESCRIPTION

The {{i:`nng_thread`}} structure is used to represent a {{i:thread}} of execution.

In NNG, a thread has an execution fuction _func_, and can be assumed to run this concurrently
to other threads, including the main thread of the application. The thread persists
until the function _func_ returns.

> [!TIP]
> The detail of whether the thread represents an operating system thread,
> a process, or a "green" thread (also known as a a fiber or coroutine) is determined by the platform.
> Portable applications should avoid depending on this implementation detail.

The `nng_thread_create` function creates a thread,
running _func_ with the argument _arg_.
The thread is started immediately.
A pointer to the thread object is returned in _thrp_.

Using threads created by this function can make it easy to write
programs that use simple sequential execution, using functions in the
_NNG_ suite that would otherwise normally wait synchronously for completion.

When the thread is no longer needed, the {{i: `nng_thread_destroy`}}
function should be used to reap it.
(This function will block waiting for _func_ to return.)

> [!IMPORTANT]
> Thread objects created by this function may not be real system-level
> threads capable of performing blocking I/O operations using normal blocking system calls.
> If use of blocking system calls is required (not including APIs provided
> by the _NNG_ library itself of course), then real OS-specific threads
> should be created instead (such as with `pthread_create` or similar functions.)

> [!IMPORTANT]
> Thread objects created by this function cannot be passed to any system threading functions.

> [!TIP]
> The system may impose limits on the number of threads that can be created.
> Typically applications should not create more than a dozen of these.
> If greater concurrency or scalability is needed, consider instead using
> an asynchronous model using [`nng_aio`][aio] structures.

> [!TIP]
> Threads can be synchronized using [mutexes][mutex] and
> [condition variables][condvar].

In order to facilitate debugging, {{i:`nng_thread_set_name`}} may be called
to provide a name for the thread. This may change how the thread is represented
in debuggers. Not all platforms support setting the thread name.

## RETURN VALUES

The `nng_thread_create` function returns 0 on success, and non-zero otherwise.

## ERRORS

- `NNG_ENOMEM`: Insufficient free memory exists.

## SEE ALSO

[nng_cv][condvar],
[nng_mutex][mutex]

[condvar]: ../thr/nng_cv.md
[mutex]: ../thr/nng_mtx.md
[aio]: TODO.md
