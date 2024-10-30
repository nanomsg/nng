// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.

#include <stdio.h>

#include <nng/nng.h>

int
main(int argc, char **argv)
{
	printf("NNG version is: %s\n", nng_version());
	return (0);
}
