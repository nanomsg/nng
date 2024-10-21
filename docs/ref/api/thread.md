# Threads

Threads {{hi:threads}} provide a means of representing multiple parallel execution contexts.
_NNG_ makes use of this concept internally, but also provides for user applications
to utilize the same thread facilities. This allows one form of {{i:concurrency}} for
applications.

> [!NOTE]
> Threads in _NNG_ are built upon platform support, which may be based upon operating
> system supplied threads, process, or coroutines. The appearance of concurrency does
> not guarantee true concurrency, and scheduling between threads may not necessarily be
> pre-emptive. While this will not adversely impact applications that use this facility
> for I/O bound concurrency, it may not provide good results for purely {{i:CPU-bound}} operations.

> [!IMPORTANT]
> Thread objects created by this function may not be real system-level
> threads capable of performing blocking I/O operations using normal blocking system calls.
> If use of blocking system calls is required (not including APIs provided
> by the _NNG_ library itself of course), then real OS-specific threads
> should be created instead (such as with `pthread_create` or similar functions.)
> Blocking _NNG_ library calls can however be made safely from _NNG_ threads.

> [!TIP]
> The system may impose limits on the number of threads that can be created.
> Typically applications should not create more than a dozen of these.
> If greater concurrency or scalability is needed, consider instead using
> an asynchronous model using [`nng_aio`][aio] structures.

## Thread Structure

```c
typedef struct nng_thread nng_thread;
```

The {{i:`nng_thread`}} structure represnts a thread, which is a single execution context.
A given thread will have its own stack, and CPU registers. However global state, as well
as values allocated on the heap, will be shared and accessible to all threads in the system
(See the [Synchronization][synchronization] chapter for functions to help with data sharing between different threads.)

Multiple threads can be thought of as running concurrently, even though
they might not actually do so.

I/O operations that block (i.e. wait for completion) will block the
thread, while allowing other threads to proceed.

## Creating a Thread

```c
int nng_thread_create(nng_thread **thrp, void (*func)(void *), void *arg);
```

The {{i:`nng_thread_create`}} function creates a thread, which will execute _func_, with
the given argument _arg_, and returns a pointer to it in _thrp_.

The thread may begin execution immediately.

The thread will persist until _func_ returns.

This function returns zero on success, but may return `NNG_ENOMEM` if insufficient
resources to create a thread are available.

## Destroying a Thread

```c
void nng_thread_destroy(nng_thread *thr);
```

The {{i:`nng_thread_destroy`}} function waits for the thread _thr_ to finish execution.
This function should be called to reclaim any resources associated with the thread when done.
It also has the effect of blocking execution in the caller until _thr_ has completed executing.

## Thread Names

```c
void nng_thread_set_name(nng_thread *thr, const char *name);
```

In order to facilitate debugging, {{i:`nng_thread_set_name`}} may be called
to provide a name for the thread. This may change how the thread is represented
in debuggers. Not all platforms support setting the thread name.

## See Also

[Synchronization][synchronization],
[Asynchronous Operations][aio]

[synchronization]: ../api/synch.md
[aio]: TODO.md
