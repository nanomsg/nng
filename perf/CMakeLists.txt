#
#   Copyright (c) 2012 Martin Sustrik  All rights reserved.
#   Copyright (c) 2013 GoPivotal, Inc.  All rights reserved.
#   Copyright (c) 2015-2016 Jack R. Dunaway. All rights reserved.
#   Copyright 2016 Garrett D'Amore <garrett@damore.org>
#   Copyright 2016 Franklin "Snaipe" Mathieu <franklinmathieu@gmail.com>
#   Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
#
#   Permission is hereby granted, free of charge, to any person obtaining a copy
#   of this software and associated documentation files (the "Software"),
#   to deal in the Software without restriction, including without limitation
#   the rights to use, copy, modify, merge, publish, distribute, sublicense,
#   and/or sell copies of the Software, and to permit persons to whom
#   the Software is furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included
#   in all copies or substantial portions of the Software.
#
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
#   THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#   FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
#   IN THE SOFTWARE.
#

#  Build performance tests.

include_directories(AFTER SYSTEM ${PROJECT_SOURCE_DIR}/src)

if (NNG_TESTS)
     macro (add_nng_perf NAME)
        add_executable (${NAME} perf.c)
        target_link_libraries (${NAME} ${PROJECT_NAME})
        target_compile_definitions(${NAME} PUBLIC)
    endmacro (add_nng_perf)

    add_nng_perf(remote_lat)
    add_nng_perf(local_lat)
    add_nng_perf(local_thr)
    add_nng_perf(remote_thr)
    add_nng_perf(inproc_thr)
    add_nng_perf(inproc_lat)

    add_test (NAME inproc_lat COMMAND inproc_lat 64 10000)
    set_tests_properties (inproc_lat PROPERTIES TIMEOUT 30)

    add_test (NAME inproc_thr COMMAND inproc_thr 1400 10000)
    set_tests_properties (inproc_thr PROPERTIES TIMEOUT 30)


    add_executable (pubdrop pubdrop.c)
    target_link_libraries(pubdrop ${PROJECT_NAME})
    target_compile_definitions(pubdrop PUBLIC)

endif ()
