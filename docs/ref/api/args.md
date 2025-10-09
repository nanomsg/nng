# Command Arguments

Some NNG utilities need to parse command line options,
and for this purpose a header library is supplied.

To make use of this, the header `<nng/args.h>` must be included.

> [!TIP]
> The functionality described here is entirely contained in the
> `nng/args.h` header file, and may be used without previously
> initializing the library with [`nng_init`], and may even be used
> in programs that are not linked against the NNG library.

## Parse Command Line Arguments

```c
typedef struct nng_arg_spec {
    const char *a_name;  // Long style name (may be NULL for short only)
    int         a_short; // Short option (no clustering!)
    int         a_val;   // Value stored on a good parse (>0)
    bool        a_arg;   // Option takes an argument if true
} nng_optspec;

#define NNG_ARG_END     (-1)
#define NNG_ARG_INVAL   (-2)
#define NNG_ARG_AMBIG   (-3)
#define NNG_ARG_MISSING (-4)

int nng_args_parse(int argc, char *const *argv,
                   const nng_optspec *spec, int *val, char **arg, int *idx);
```

The {{i:`nng_args_parse`}} function is intended to facilitate parsing
{{i:command-line arguments}}.
This function exists largely to stand in for {{i:`getopt`}} from POSIX systems,
but it is available on all platforms, and it includes some capabilities missing from `getopt`.

The function parses arguments from
`main`{{footnote: Parsing argument strings from other sources can be done as well,
although usually then _idx_ will be initialized to zero.}}
(using _argc_ and _argv_),
starting at the index referenced by _idx_.
(New invocations typically set the value pointed to by _idx_ to 1.)

Options are parsed as specified by _spec_ (see [Argument Specification](#argument-specification).)
The value of the parsed option will be stored at the address indicated by
_val_, and the value of _idx_ will be incremented to reflect the next
option to parse.

> [!TIP]
> For using this to parse command-line like strings that do not include
> the command name itself, set the value referenced by _idx_ to zero instead of one.

If the option had an argument, a pointer to that is returned at the address
referenced by _arg_.

This function should be called repeatedly, until it returns either -1
(indicating the end of options is reached) or a non-zero error code is
returned.

This function may return the following errors:

- `NNG_ARG_AMBIG`: Parsed option matches more than one specification.
- `NNG_ARG_MISSING`: Option requires an argument, but one is not present.
- `NNG_ARG_INVAL`: An invalid (unknown) argument is present in _argv_.

### Option Specification

The calling program must first create an array of {{i:`nng_arg_spec`}} structures
describing the options to be supported.
This structure has the following members:

- `a_name`:

  The long style name for the option, such as "verbose".
  This will be parsed as a [long option](#long-options) on the command line when it is prefixed with two dashes.
  It may be `NULL` if only a [short option](#short-options) is to be supported.

- `a_short`:

  This is a single letter (at present only ASCII letters are supported).
  These options appear as just a single letter, and are prefixed with a single dash on the command line.
  The use of a slash in lieu of the dash is _not_ supported, in order to avoid confusion with path name arguments.
  This value may be set to 0 if no [short option](#short-options) is needed.

- `o_val`:

  This is a numeric value that is unique to this option.
  This value is assigned by the application program, and must be non-zero for a valid option.
  If this is zero, then it indicates the end of the specifications, and the
  rest of this structure is ignored.
  The value will be returned to the caller in _val_ by `nng_args_parse` when
  this option is parsed from the command line.

- `a_arg`:

  This value should be set to `true` if the option should take an argument.

### Long Options

Long options are parsed from the _argv_ array, and are indicated when
the element being scanned starts with two dashes.
For example, the "verbose" option would be specified as `--verbose` on
the command line.
If a long option takes an argument, it can either immediately follow
the option as the next element in _argv_, or it can be appended to
the option, separated from the option by an equals sign (`=`) or a
colon (`:`).

### Short Options

Short options appear by themselves in an _argv_ element, prefixed by a dash (`-`).
If the short option takes an argument, it can either be appended in the
same element of _argv_, or may appear in the next _argv_ element.

> [!NOTE]
> Option clustering, where multiple options can be crammed together in
> a single _argv_ element, is not supported by this function (yet).

### Prefix Matching

When using long options, the parser will match if it is equal to a prefix
of the `a_name` member of a option specification, provided that it do so
unambiguously (meaning it must not match any other option specification.)

## Example

The following program fragment demonstrates this function.

```c
    enum { OPT_LOGFILE, OPT_VERBOSE };
    char *logfile; // options to be set
    bool verbose;

    static nng_arg_spec specs[] = {
        {
            .a_name = "logfile",
            .a_short = 'D',
            .a_val = OPT_LOGFILE,
            .a_arg = true,
        }, {
            .a_name = "verbose",
            .a_short = 'V',
            .a_val = OPT_VERBOSE,
            .a_arg = false,
        }, {
            .a_val = 0; // Terminate array
        }
    };

    for (int idx = 1;;) {
        int rv, opt;
        char *arg;
        rv = nng_args_parse(argc, argv, specs, &opt, &arg, &idx);
        if (rv != 0) {
            break;
        }
        switch (opt) {
        case OPT_LOGFILE:
            logfile = arg;
            break;
        case OPT_VERBOSE:
            verbose = true;
            break;
        }
    }
    if (rv != NNG_ARG_END) {
        switch (rv) {
        case NNG_ARG_AMBIG:
            printf("Options error: ambiguous option\n");
            break;
        case NNG_ARG_MISSING:
            printf("Options error: required option argument missing\n");
            break;
        case NNG_ARG_INVAL:
            printf("Options error: unknown option present\n");
            break;
        }
        exit(1);
    }
```

{{#include ../xref.md}}
