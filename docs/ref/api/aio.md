# Asynchronous Operations

In order to obtain significant scalability, with low-latency, and minimal
overheads, _NNG_ supports performing operations asynchronously.

One way that applications can perform work asynchronously and concurrently
is by using [threads][thread], but threads carry significant resource overheads
and frequently there are limits on the number that can easily be created.

Additionally, with most network applications, the flow of execution will spend
the bulk of its time waiting for traffic from a peer.

For these kinds of applications, it is far more efficient to use asynchronous operations
using the mechanisms described in this chapter.

> [!TIP]
> To get the highest performance with the least overhead, applications should use
> asynchronous operations described in this chapter whenever possible.

## Asynchronous I/O Handle

```c
typedef struct nng_aio nng_aio;
```

An {{i:`nng_aio`}}{{hi:aio}} is an opaque structure used in conjunction with
{{i:asynchronous I/O}} operations.
Every asynchronous operation uses one of these structures, each of which
can only be used with a single operation at a time.

Asynchronous operations are performed without blocking calling application threads.
Instead the application registers a callback function to be executed
when the operation is complete (whether successfully or not).
This callback will be executed exactly once.

The asynchronous I/O framework also supports [cancellation][`nng_aio_cancel`] of
operations that are already in progress as well setting a maximum
[timeout][`nng_aio_set_timeout`] for them to complete.

It is also possible to initiate an asynchronous operation, and [wait][`nng_aio_wait`] for it to
complete, creating a synchronous flow from an asynchronous one.

## Create Handle

```c
int nng_aio_alloc(nng_aio **aiop, void (*callb)(void *), void *arg);
```

The {{i:`nng_aio_alloc`}} function creates an [`nng_aio`] object, with the
{{i:callback}} _callb_ taking the argument _arg_, and returns it in _aiop_.

If this succeeds, the function returns zero. Otherwise it may return [`NNG_ENOMEM`].

> [!TIP]
> The _arg_ should normally be a structure that contains a pointer to the _aiop_,
> or from which it can be located. This allows _callb_ to check the handle for
> success using [`nng_aio_result`], as well access other properties of _aiop_.

> [!TIP]
> The _callb_ may be executed on another [thread], so it may be necessary to use
> [synchronization] methods in _callb_ to avoid data races.

## Destroy Handle

```c
void nng_aio_free(nng_aio *aio);
void nng_aio_reap(nng_aio *aio);
```

The {{i:`nng_aio_free`}} handle destroys the handle _aio_, waiting for any operations
and associated callbacks to complete before doing so.

The {{i:`nng_aio_reap`}} handle destroys the handle _aio_ asynchronously, using a _reaper_
[thread] to do so. It does not wait for the object to be destroyed. Thus this function
is safe to call from _aio_'s own callback.

> [!NOTE]
> The `nng_aio_free` function must never be called from an _aio_ callback.
> Use `nng_aio_reap` instead if an object must be destroyed from a callback.

## Cancellation

```c
void nng_aio_abort(nng_aio *aio, int err);
void nng_aio_cancel(nng_aio *aio);
void nng_aio_stop(nng_aio *aio);
```

These functions are used to stop a previously submitted asynchronous
I/O operation. The operation may be canceled, or may continue to
completion. If no operation is in progress (perhaps because it has
already completed), then these operations have no effect.
If the operation is successfully canceled or aborted, then the callback
will still be called.

The {{i:`nng_aio_abort`}} function aborts the operation associated with _aio_
and returns immediately without waiting. If cancellation was successful,
then [`nng_aio_result`] will return _err_.

The {{i:`nng_aio_cancel`}} function acts like `nng_aio_abort`, but uses the error code
[`NNG_ECANCELED`]{{hi:`NNG_ECANCELED`}}.

The {{i:`nng_aio_stop`}} function aborts the _aio_ operation with [`NNG_ECANCELED`],
and then waits the operation and any associated callback to complete.
This function also marks _aio_ itself permanently stopped, so that any
new operations scheduled by I/O providers using [`nng_aio_begin`]
return false. Thus this function should be used to teardown operations.

> [!TIP]
> When multiple asynchronous I/O handles are in use and need to be
> deallocated, it is safest to stop all of them using `nng_aio_stop`,
> before deallocating any of them with [`nng_aio_free`],
> particularly if the callbacks might attempt to reschedule further operations.

## Set Timeout

```c
void nng_aio_set_timeout(nng_aio *aio, nng_duration timeout);
void nng_aio_set_expire(nng_aio *aio, nng_time expiration);
```

The `nng_aio_set_timeout` function sets a {{ii:timeout}}
for the asynchronous operation associated with _aio_.
This causes a timer to be started when the operation is actually started.
If the timer expires before the operation is completed, then it is
[aborted][`nng_aio_abort`] with an error of `NNG_ETIMEDOUT`.
The _timeout_ [duration][time] is specified as a relative number of milliseconds.

If the timeout is [`NNG_DURATION_INFINITE`], then no timeout is used.
If the timeout is [`NNG_DURATION_DEFAULT`], then a "default" or socket-specific
timeout is used.
(This is frequently the same as [`NNG_DURATION_INFINITE`].)

The {{i:`nng_aio_set_expire`}} function is similar to `nng_aio_set_timeout`, but sets
an expiration time based on the system clock. The _expiration_
[time] is a clock timestamp, such as would be returned by [`nng_clock`].

## Wait for Completion

```c
void nng_aio_wait(nng_aio *aio);
```

The {{i:`nng_aio_wait`}} function waits for an asynchronous I/O operation to complete.
If the operation has not been started, or has already completed, then it returns immediately.

If a callback was set with _aio_ when it was allocated, then this
function will not be called until the callback has completed.

> [!IMPORTANT]
> The `nng_aio_wait` function should never be called from a function that itself
> is a callback of an [`nng_aio`], either this one or any other.
> Doing so may result in a deadlock.

## Test for Completion

```c
bool nng_aio_busy(nng_aio *aio);
```

The {{i:`nng_aio_busy`}} function returns `true` if the _aio_ is currently busy performing an
operation or is executing a completion callback. Otherwise it return `false`.
This is the same test used internally by [`nng_aio_wait`].

> [!IMPORTANT]
> The caller is responsible for coordinating any use of this with any reuse of the _aio_.
> Because the _aio_ can be reused use of this function can be racy.

## Result of Operation

```c
int nng_aio_result(nng_aio *aio);
size_t nng_aio_count(nng_aio *aio);
```

The {{i:`nng_aio_result`}} function returns the result of the operation associated
with the handle _aio_.
If the operation was successful, then 0 is returned.
Otherwise a non-zero [error] code, such as [`NNG_ECANCELED`] or [`NNG_ETIMEDOUT`], is returned.

For operations that transfer data, {{i:`nng_aio_count`}} returns the
number of bytes transferred by the operation associated with the handle _aio_.
Operations that do not transfer data, or do not keep a count, may return zero for this function.

> [!NOTE]
> The return value from these functions is undefined if the operation has not completed yet.
> Either call these from the handle's completion callback, or after waiting for the
> operation to complete with [`nng_aio_wait`].

## Messages

```c
nng_msg *nng_aio_get_msg(nng_aio *aio);
void nng_aio_set_msg(nng_aio *aio, nng_msg *msg);
```

The {{i:`nng_aio_get_msg`}} and {{i:`nng_aio_set_msg`}} functions retrieve and store a [message]
in _aio_.
For example, if a function to receive data is called, that function can generally be expected
to store a message on the asssociated _aio_, for the application to retrieve with
`nng_aio_get_msg`.
Conversely an application desiring to send a message _msg_ will store it in the _aio_ using
`nng_aio_set_msg`. The function implementing the send operation will retrieve the message
and arrange for it to be sent.

### Message Ownership

For send or transmit operations, the rule of thumb is that implementation of the operation
is responsible for taking ownership of the message (and releasing resources when it is complete),
if it will return success. If the operation will end in error, then the message will be
retained and it is the consuming application's responsibility to dispose of the message.
This allows an application the opportunity to reuse the message to try again, if it so desires.

For receive operations, the implementation of the operation will set the message on the _aio_
on success, and the consuming application hasa responsibility to retrieve and dispose of the
message. Failure to do so will leak the message. If the operation does not complete successfully,
then no message is stored on the _aio_.

## I/O Vector

```c
typedef struct nng_iov {
    void * iov_buf;
    size_t iov_len;
};

int nng_aio_set_iov(nng_aio *aio, unsigned int niov, nng_iov *iov);
```

For some operations, the unit of data transferred is not a [message], but
rather a stream of bytes.

For these operations, an array of _niov_ {{i:`nng_iov`}} structures can be passed to
the {{i:`nng_aio_set_iov`}} function to provide a scatter/gather array of
elements describing the location (`iov_buf`) and length (`iov_len`) of data,
to transfer.

The _iov_ vector is copied into storage in the _aio_ itself, so that callers may use stack allocated `nng_iov` structures.
The values pointed to by the `iov_buf` members are _not_ copied by this function though.

A maximum of four (4) `nng_iov` members may be supplied.

> [!TIP]
> Most functions using `nng_iov` do not guarantee to transfer all of the data that they
> are requested to. To be sure that correct amount of data is transferred, as well as to
> start an attempt to complete any partial transfer, check the amount of data transferred by
> calling [`nng_aio_count`].

## Inputs and Outputs

```c
void nng_aio_set_input(nng_aio *aio, unsigned int index, void *param);
void *nng_aio_get_output(nng_aio *aio, unsigned int index);
```

Asynchronous operations can take additional input parameters, and
provide additional result outputs besides the [result][`nng_aio_result`] code.

The `nng_aio_set_input` function sets the input parameter at _index_
to _param_ for the operation associated with _aio_.

The `nng_aio_get_output` function returns the output result at _index_
for the operation associated with _aio_.

The type and semantics of input parameters and output results are determined by specific
operations. The documentation for the operation should provide details.

The valid values of _index_ range from zero (0) to three (3), as no operation
currently defined can accept more than four parameters or return more than four additional
results.

> [!NOTE]
> If the _index_ does not correspond to a defined input for the operation,
> then `nng_aio_set_input` will have no effect, and `nng_aio_get_output` will
> return `NULL`.

> [!IMPORTANT]
> It is an error to call this function while the _aio_ is currently
> in use by an active asynchronous operation.

## See Also

[Synchronization][synchronization],
[Threads][thread],
[Time][time]

{{#include ../xref.md}}
