#pragma once

#include "common.h"
#include "ringbuf_generic.h"

// ——————————————————— Type for the shared memory region ———————————————————— //

RB_DECLARE_TYPE(char);
RB_DECLARE_PROTOS(char);

#define MSG_BUFFER_SIZE 1048

/// The seal enclave shared memory gets typecasted to this.
typedef struct seal_app_t {
	// Sending things to seal.
	rb_char_t to_seal;
	// Receiving messages from seal.
	rb_char_t from_seal;
	// Buffer for the to_seal.
	char to_buffer[MSG_BUFFER_SIZE];
	// Buffer for the from_seal.
	char from_buffer[MSG_BUFFER_SIZE];
} seal_app_t;

// —————————————————————————— Server configuration —————————————————————————— //
/// Port for the server.
extern unsigned int NET_PORT;
/// Size of tcp buffer.
#define NET_BUFFER_SIZE 1048

// ———————————————————————————— Common functions ———————————————————————————— //
/// Helps pinning the thread to the core.
int pin_self_to_core(usize core);
// —————————————————————————— TCP server functions —————————————————————————— //
/// The server that accepts connections.
int tcp_start_server(usize core, seal_app_t* comm);

/// The main runner for a single connection.
void* tcp_connection_handler(void* socket_desc);

// ————————————————————————— STDIN server functions ————————————————————————— //

/// Simple stdin server.
int stdin_start_server(usize core, seal_app_t* comm);
