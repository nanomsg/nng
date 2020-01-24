#!/bin/sh
#
# Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#
#
cat <<EOF
*** DO NOT USE THIS SCRIPT ***

We moved this to the gh-pages branch.

To publish updates:

  * git checkout the gh-pages branch
  * run the _tools/pubrefman.sh script in gh-pages
  * _tools/pubrefman.sh can take a tag (e.g. "v1.2.4") as an argument
  * push the gh-pages branch

EOF
exit 1