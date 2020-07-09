// Copyright 2020 Hugo Lindström <hugolm84@gmail.com>

// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.

#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>

void
wsa_fatal(const char *func)
{
	fprintf(stderr, "%s: %d\n", func, WSAGetLastError());
	exit(1);
}

int
server(int portno)
{
	WSADATA            wsa;
	SOCKET             s, new_socket;
	struct sockaddr_in server, client;
	int                c;
	char *             message;

	printf("Initialising Winsock...\n");

	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		wsa_fatal("Failed to call WSAStartup");
	}

	printf("Initialised WSA.\n");

	// Create a socket
	if ((s = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
		wsa_fatal("Could not create socket");
	}

	printf("Socket created.\n");

	// Prepare the sockaddr_in structure
	server.sin_family      = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port        = htons(portno);

	// Bind
	if (bind(s, (struct sockaddr *) &server, sizeof(server)) ==
	    SOCKET_ERROR) {
		wsa_fatal("Bind failed");
	}

	printf("Bind done\n");

	// Listen to incoming connections
	listen(s, 3);

	// Accept and incoming connection
	printf("Waiting for incoming connections...\n");

	c = sizeof(struct sockaddr_in);

	while ((new_socket = accept(s, (struct sockaddr *) &client, &c)) !=
	    INVALID_SOCKET) {
		printf("Connection accepted\n");
		// Reply to the client
		message = "Hello Client!";
		if (send(new_socket, message, (int) strlen(message), 0) ==
		    SOCKET_ERROR) {
			wsa_fatal("Failed to send message to client!");
		}
	}

	if (new_socket == INVALID_SOCKET) {
		wsa_fatal("accept failed");
	}

	if (closesocket(s) == SOCKET_ERROR) {
		wsa_fatal("Failed to close socket");
	}

	if (WSACleanup() == SOCKET_ERROR) {
		wsa_fatal("Failed to WSACleanup");
	}
	return 0;
}
