#
# Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# Surveyor/Respondent protocol
option (NNG_PROTO_RESPONDENT0 "Enable RESPONDENTv0 protocol." ON)
mark_as_advanced(NNG_PROTO_RESPONDENT0)

option (NNG_PROTO_SURVEYOR0 "Enable SURVEYORv0 protocol." ON)
mark_as_advanced(NNG_PROTO_SURVEYOR0)

nng_sources_if(NNG_PROTO_SURVEYOR0 survey.c xsurvey.c)
nng_headers_if(NNG_PROTO_SURVEYOR0 nng/protocol/survey0/survey.h)
nng_defines_if(NNG_PROTO_SURVEYOR0 NNG_HAVE_SURVEYOR0)

nng_sources_if(NNG_PROTO_RESPONDENT0 respond.c xrespond.c)
nng_headers_if(NNG_PROTO_RESPONDENT0 nng/protocol/survey0/respond.h)
nng_defines_if(NNG_PROTO_RESPONDENT0 NNG_HAVE_RESPONDENT0)

nng_test(respond_test)
nng_test(survey_test)
nng_test(xrespond_test)
nng_test(xsurvey_test)