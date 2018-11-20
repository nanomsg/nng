/*
    Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
    Copyright 2018 Capitar IT Group BV <info@capitar.com>

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom
    the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included
    in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
    IN THE SOFTWARE.
*/

#include <nng/compat/nanomsg/nn.h>
#include <nng/compat/nanomsg/pair.h>
#include "compat_testutil.h"

int main (NN_UNUSED int argc, NN_UNUSED const char *argv[])
{
    int sb;
    int sc1;
    int sc2;

    sb = test_socket (AF_SP, NN_PAIR);
    test_bind (sb, "inproc://pair");
    sc1 = test_socket (AF_SP, NN_PAIR);
    test_connect (sc1, "inproc://pair");
    nn_sleep (100);
    sc2 = test_socket (AF_SP, NN_PAIR);
    test_connect (sc2, "inproc://pair");

    test_send (sb, "HELLO");
    test_recv (sc1, "HELLO");

    test_send (sc1, "THERE");
    test_recv (sb, "THERE");
    return 0;
}
