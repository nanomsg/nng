//
// Copyright (c) 2014 Wirebird Labs LLC.  All rights reserved.
// Copyright 2017 Staysail Systems, Inc. <info@staysail.tech>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom
// the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.
//

#ifndef NNI_BASE64_INCLUDED
#define NNI_BASE64_INCLUDED

#include <stddef.h>
#include <stdint.h>

// Based on base64.c (Public Domain) by Jon Mayo.
// Base64 is defined in RFC 2045, section 6.8.

// This function encodes an arbitrary byte array into base64
// null-terminated string.
int nni_base64_encode(const uint8_t *, size_t, char *, size_t);

// This function decodes a base64 string into supplied buffer.
int nni_base64_decode(const char *, size_t, uint8_t *, size_t);

#endif
