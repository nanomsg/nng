//
// Copyright 2024 Aleksei Solovev <solovalex@gmail.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <assert.h>
#include <nng/nng.h>
#include <core/nng_impl.h>
#include <nng/protocol/survey0/survey.h>
#include <nng/protocol/survey0/respond.h>
#include <nng/protocol/reqrep0/req.h>
#include <nng/protocol/reqrep0/rep.h>

#include <nuts.h>

enum state {
	SEND,
	RECV,
};

struct work;
typedef void (*work_fn)(struct work *);

struct work {
	work_fn    start;
	nng_socket socket;
	nng_aio *  aio;
	enum state state;
	nni_atomic_int received;
};

void
fatal(const char *msg, int result)
{
	fprintf(stderr, "%s: %s\n", msg, nng_strerror(result));
	abort();
}

#define PASS(cond)                 \
	do {                           \
		int result_ = (cond);      \
		if (result_ != 0)          \
			fatal(#cond, result_); \
	} while (0)

void
work_send(struct work *w, void *data, size_t size)
{
	nng_msg *msg;

	w->state = SEND;
	PASS(nng_msg_alloc(&msg, 0));
	PASS(nng_msg_append(msg, data, size));
	nng_aio_set_msg(w->aio, msg);
	nng_send_aio(w->socket, w->aio);
}

void
free_aio_msg(struct work *w)
{
	nng_msg *msg;

	msg = nng_aio_get_msg(w->aio);
	if (msg)
		nng_msg_free(msg);
}

void
work_listen(struct work *w, const char *url)
{
	PASS(nng_listen(w->socket, url, NULL, 0));
}

void
work_dial(struct work *w, const char * const * urls, size_t urls_size)
{
	size_t i;

	for (i = 0; i < urls_size; ++i)
		PASS(nng_dial(w->socket, urls[i], NULL, 0));
}

void
close_work(struct work *w)
{
	nng_close(w->socket);
	nng_aio_wait(w->aio);
	nng_aio_free(w->aio);
}

void
ping_start(struct work *w)
{
	work_send(w, "ping", 5);
}

void
ping_cb(void *arg)
{
	nng_msg *msg;
	struct work *w = arg;
	int result = nng_aio_result(w->aio);

	if (result)
		switch (result) {
			case NNG_ETIMEDOUT:
			case NNG_ESTATE:
				free_aio_msg(w);
				ping_start(w);
				return;
			case NNG_ECANCELED:
			case NNG_ECLOSED:
				free_aio_msg(w);
				return;
			default:
				fatal("ping_cb", result);
		}

	switch (w->state) {
		case SEND:
			w->state = RECV;
			nng_recv_aio(w->socket, w->aio);
			break;
		case RECV:
			msg = nng_aio_get_msg(w->aio);
			assert(msg != NULL);
			assert(nng_msg_len(msg) == 5);
			assert(0 == strncmp(nng_msg_body(msg), "echo", 4));
			nng_msg_free(msg);
			nni_atomic_inc(&w->received);
			ping_start(w);
			break;
	}
}

void
echo_start(struct work *w)
{
	w->state = RECV;
	nng_recv_aio(w->socket, w->aio);
}

void
echo_cb(void *arg)
{
	nng_msg *msg;
	struct work *w = arg;
	int result = nng_aio_result(w->aio);

	if (result)
		switch (result) {
			case NNG_ECANCELED:
			case NNG_ECLOSED:
				free_aio_msg(w);
				return;
			default:
				fatal("echo_cb", result);
		}

	switch (w->state) {
		case RECV:
			msg = nng_aio_get_msg(w->aio);
			assert(msg != NULL);
			assert(nng_msg_len(msg) == 5);
			assert(0 == strncmp(nng_msg_body(msg), "ping", 4));
			nng_msg_free(msg);
			nni_atomic_inc(&w->received);
			work_send(w, "echo", 5);
			break;
		case SEND:
			echo_start(w);
			break;
	}
}

#define CLIENTS_COUNT      64
#define SERVICES_COUNT     8
#define CLIENT_RX_COUNT    100
#define TEST_DURATION_MS   3000
#define SURVEY_TIMEOUT_MS  100

void
surveyor_open(struct work *w)
{
	w->start = ping_start;
	NUTS_PASS(nng_surveyor_open(&w->socket));
	NUTS_PASS(nng_socket_set_ms(w->socket, NNG_OPT_SURVEYOR_SURVEYTIME, SURVEY_TIMEOUT_MS));
	NUTS_PASS(nng_aio_alloc(&w->aio, ping_cb, w));
	nni_atomic_init(&w->received);
}

void
respondent_open(struct work *w)
{
	w->start = echo_start;
	NUTS_PASS(nng_respondent_open(&w->socket));
	NUTS_PASS(nng_aio_alloc(&w->aio, echo_cb, w));
	nni_atomic_init(&w->received);
}

void
req_open(struct work *w)
{
	w->start = ping_start;
	NUTS_PASS(nng_req_open(&w->socket));
	NUTS_PASS(nng_aio_alloc(&w->aio, ping_cb, w));
	nni_atomic_init(&w->received);
}

void
rep_open(struct work *w)
{
	w->start = echo_start;
	NUTS_PASS(nng_rep_open(&w->socket));
	NUTS_PASS(nng_aio_alloc(&w->aio, echo_cb, w));
	nni_atomic_init(&w->received);
}

void
run_test(work_fn open_service, work_fn open_client)
{
	int i;
	nng_time stop_time;
	struct work * service;
	struct work * client;
	struct work services[SERVICES_COUNT];
	struct work clients [CLIENTS_COUNT];

	const char * service_urls[SERVICES_COUNT] = {
		"inproc://stressA",
		"inproc://stressB",
		"inproc://stressC",
		"inproc://stressD",
		"inproc://stressE",
		"inproc://stressF",
		"inproc://stressG",
		"inproc://stressH",
	};

	for (i = 0; i < SERVICES_COUNT; i++) {
		service = &services[i];
		(*open_service)(service);
		work_listen(service, service_urls[i]);
		(*service->start)(service);
	}

	for (i = 0; i < CLIENTS_COUNT; i++) {
		client = &clients[i];
		(*open_client)(client);
		work_dial(client, service_urls, SERVICES_COUNT);
		(*client->start)(client);
	}

	stop_time = nng_clock() + TEST_DURATION_MS;
	while (nng_clock() < stop_time) {
		client = &clients[nng_random() % CLIENTS_COUNT];
		while (nni_atomic_get(&client->received) < CLIENT_RX_COUNT)
			nng_msleep(1);
		close_work(client);
		(*open_client)(client);
		work_dial(client, service_urls, SERVICES_COUNT);
		(*client->start)(client);
	}

	for (i = 0; i < CLIENTS_COUNT; i++)
		close_work(&clients[i]);
	for (i = 0; i < SERVICES_COUNT; i++)
		close_work(&services[i]);
}

void
reconnect_stress_respondent(void)
{
	run_test(respondent_open, surveyor_open);
}

void
reconnect_stress_surveyor(void)
{
	run_test(surveyor_open, respondent_open);
}

void
reconnect_stress_rep(void)
{
	run_test(rep_open, req_open);
}

void
reconnect_stress_req(void)
{
	run_test(req_open, rep_open);
}

TEST_LIST = {
	{ "reconnect stress respondent", reconnect_stress_respondent },
	{ "reconnect stress surveyor", reconnect_stress_surveyor },
	{ "reconnect stress rep", reconnect_stress_rep },
	{ "reconnect stress req", reconnect_stress_req },
	{ NULL, NULL },
};
