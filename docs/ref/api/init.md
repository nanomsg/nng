# Initialization & Finalization

This chapter details the function used to initialize
the library before first use, and the funtion used to
finalize the library and deallocate any resources used by the library.

## Initialization

```c
typedef struct {
    int16_t num_task_threads;
    int16_t max_task_threads;
    int16_t num_expire_threads;
    int16_t max_expire_threads;
    int16_t num_poller_threads;
    int16_t max_poller_threads;
    int16_t num_resolver_threads;
} nng_init_params;

extern int nng_init(nng_init_parms *params);
```

Before using other interfaces in this library, it is necessary to initialize
the library. The {{i:`nng_init`}} function performs this initialization.

The function is idempotent, although on tear down, every call to `nng_init` must
be paired with a call to [`nng_fini`] or no resources will be released.
This allows for libraries consuming these interfaces to safely initialize and finalize
the library without disrupting other consumers in the same process.

Further, only the first call to this function may have a value of _params_ other than `NULL`.
If _params_ is not `NULL`, and the library has already been intiazed, then `nng_init` will
return [`NNG_EBUSY`].

In some cases it is desirable to tune certain runtime parameters for the library, which
can be done by supplying a non-`NULL` _params_ argument.

### Parameters

The individual fields of the `nng_init_params` structure can be used to adjust certain
runtime tunables for the library. There is no guarantee that these tunables are implemented,
and applications should not depend upon them for correct operation.

Any member of `nng_init_params` that is set to zero will be ignored, and any built in default
will be used instead for that value.

> [!NOTE]
> Applications should make sure that structure is zero initialized before calling `nng_init`.

The following parameters are present:

- `num_task_threads` and `max_task_threads` \
  Configures the number of threads to use for tasks, which are used principally for completion
  callbacks. The maximum value can be used to provide an upper limit while still allowing
  for a dynamically calculated value to be used, as long as it does not exceeed the maximum.

- `num_expire_threads` and `max_expire_threads` \
  Configures the number of threads used for expiring operations. Using a larger value will
  reduce contention on some common locks, and may improve performance.

- `num_poller_threads` and `max_poller_threads` \
  Configures the number of threads to be used for performing I/O. Not all configurations support
  changing these values.

- `num_resolver_threads` \
  Changes the number of threads used for asynchronous DNS look ups.

## Finalization

```c
extern void nng_init(nng_init_parms *params);
```

When the consumer is ready to deallocate any resoures allocated by the library, it should call
the {{i:`nng_fini`}} function. Each call to `nng_fini` should be paired with an earlier call to
[`nng_init`].

After calling `nng_fini`, the consuming application must not make any other calls to NNG functions,
except that it may use `nng_init` to initialize the application for further use.

{{#include ../xref.md}}
