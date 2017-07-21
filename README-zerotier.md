zerotier branch
===============

This branch of nng represents work in progress towards a new transport
based on ZeroTier.  ZeroTier provides a virtual Ethernet switch with
planet-wide scope, offer L2 (and L3 but we dont use L3) services; thees
look like Ethernet frames but MTUs are at least 2800 bytes, and are
protected by strong crypto, which ensures messages are not forged,
snooped, or replayed.

As of this date (July 21, 2017), this work uses the libzerotiercore
library available from github.com:ZeroTier/ZeroTierOne.  You will need
to use the dev branch to build, as the seperate library is not available
in master branch.

An RFC documenting the transport is located in the main nanomsg RFC
repository.

Needless to say, this is all HIGHLY experimental.

This work is being funded by Capitar IT Group BV <info@capitar.com>.
