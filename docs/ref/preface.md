# Preface

> [!IMPORTANT]
> This is a _DRAFT_ version of this reference manual,
> and much is still in progress. There may be errors,
> and large omissions as content is still be moved from
> the previous ASCIIDOCTOR format and updated for NNG 2.0.

## Preface for the First Edition

At the time of this writing, we are wrapping up NNG for its formal
1.0.0 release.
It's a good time for reflection on the road that we took to get here.
Like the road on the cover of this book, it was windy (if quite a bit longer),
but what we find at the end has made the journey worthwhile.

Originally the NNG project was conceived as a relatively modest effort
to rewrite nanomsg based on threads, with a more readily extensible
internal architecture so that we could more easily undertake projects like the
ZeroTier and TLS transports.

It would not be incorrect to say that the initial NNG effort was started
in "anger", as we were frustrated with nanomsg's very complex internal
state machines.
Looking back on it now, those complex state state machines don't seem nearly
as insane as they did just a year ago.

The simple, na&#239;ve, approach we would have preferred, and the one we
originally started with, involved significant use of threads, inspired by the
work we did in mangos, which uses Go's goroutines heavily.
Goroutines are excellent.
Threads, it turns out, are not.
Scalable, asynchronous, _portable_ I/O is a lot harder than it looks.

> Our experience with in-kernel threads on illumos and Solaris
> spoiled us, and left us utterly unprepared for cesspool that really is
> large amounts of userspace programming.

Instead, we have created our own, completely asynchronous core, giving
us advanced multiprocessing and concurrency capabilities, without either
sacrificing portability or settling for some unhappy least common denominator.
This core is a robust foundation for NNG and handling the
"Scalability Protocols", but if we're being completely honest, we think this
core has braod applicability for beyond just the Scalability Protocols.
It will be interesting to see if others come to the same conclusion.

Builting upon this robust foundation, we have engineered a substantial
project, with capabilities far in exceess of the original nanomsg, while
still preserving compatibility with the the network protocols that
form the backbone of the nanomsg ecosystem,
and even a compatible programming interface for nanomsg library users.
In addition to compatibility with nanomsg, we find that NNG has greatly
increased scalability, reliability, and usability (especially when developing
concurrent applications).

NNG also has complete HTTP server and client
implementations, support for TLS, and a plethora of other capabilities.
Much of this is made possible by a the aforementioned asynchronous I/O
framework.

We've tried to stay true to the core nanomsg goals about being light-weight,
liberally licensed, and implemented in C.
(After all, those were the things that drew us to nanomsg in the first place!)
In addition we added a couple of new ones.
Specifically, reliability, performance, and extensibility (in that order)
were added as core goals for the project.

We believe that NNG represents a substantial step forward over other
messaging frameworks, and have enjoyed creating it.
We hope you find it useful.
There is still a lot more we want to do, and future release of NNG
will continue to expand it's capabilities.
We're just getting started.

**--- Garrett D'Amore**, May 30, 2018

## Acknowledgements

We would like to thank Janjaap Bos, at Capitar IT Group BV.
Without his patronage, neither NNG nor this book would be possible.

We would also like thank Martin S&#250;strik for creating the original
nanomsg project, the foundation upon which all of this work is based.

And certainly not least of all, we would like to thank the various
members of the community who have followed
and supported the NNG project in so many different ways.

### Conventions

Throughout this book there are occasional warnings, notices, and tips.
These are visually distinguished as follows:

> [!TIP]
> Tips are things that the reader may find useful, such as suggestions
> for use or tim saving hints.

> [!NOTE]
> Notes are things that the reader should be aware of, and provide
> additional information or context that may aid in the understanding
> or use of the topic.

> [!IMPORTANT]
> Warnings are used to denote important cautionary advice,
> which should be carefully heeded.
> Ignoring such advice may lead to crashses, unexpected behavior,
> loss of revenue, or other undesirable conditions.
