/**
 * \file psa_sim_serialise.h
 *
 * \brief Rough-and-ready serialisation and deserialisation for the PSA Crypto simulator
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include <stdint.h>
#include <stddef.h>

#include "psa/crypto.h"
#include "psa/crypto_types.h"
#include "psa/crypto_values.h"

// Basic idea:
//
// For each type foo (e.g. psa_algorithm_t, size_t, but also "buffer" where
// "buffer" is a (uint8_t *, size_t) pair, have:
// psasim_serialise_foo() and
// psasim_deserialise_foo() and
//
// We also have
// psasim_serialise_foo_needs() and
// psasim_deserialise_foo_needs() functions, which return size_t the number
// of bytes that serialising that instance of each type will need. That will
// enable us to size the buffer for serialisation.
//
// The buffer should start with a byte that indicates the sizes of basic C
// types, and four that indicate the endianness (to avoid incompatibilities
// if we ever run this over a network). We are not aiming for universality,
// just for correctness and simplicity.


// This is the client-side version of psa_hash_compute().
// It serialises arguments, calls the server, then deserialises response.
// It takes the same input arguments as the function it mimics (psa_hash_compute)
// and returns the same type.

// _serialise_ calls  should probably have a "size_t *remaining" parameter after pos:

size_t psasim_serialise_begin_needs(void);

int psasim_serialise_begin(uint8_t **pos, size_t *remaining);

int psasim_deserialise_begin(uint8_t **pos, size_t *remaining);

size_t psasim_serialise_unsigned_int_needs(unsigned int value);

int psasim_serialise_unsigned_int(uint8_t **pos, size_t *remaining, unsigned int value);

int psasim_deserialise_unsigned_int(uint8_t **pos, size_t *remaining, unsigned int *value);

size_t psasim_serialise_int_needs(int value);

int psasim_serialise_int(uint8_t **pos, size_t *remaining, int value);

int psasim_deserialise_int(uint8_t **pos, size_t *remaining, int *value);

size_t psasim_serialise_psa_status_t_needs(int value);

int psasim_serialise_psa_status_t(uint8_t **pos, size_t *remaining, int value);

int psasim_deserialise_psa_status_t(uint8_t **pos, size_t *remaining, int *value);

size_t psasim_serialise_psa_algorithm_t_needs(psa_algorithm_t value);

int psasim_serialise_psa_algorithm_t(uint8_t **pos, size_t *remaining, psa_algorithm_t value);

int psasim_deserialise_psa_algorithm_t(uint8_t **pos, size_t *remaining, psa_algorithm_t *value);

size_t psasim_serialise_size_t_needs(size_t value);

int psasim_serialise_size_t(uint8_t **pos, size_t *remaining, size_t value);

int psasim_deserialise_size_t(uint8_t **pos, size_t *remaining, size_t *value);

size_t psasim_serialise_buffer_needs(const uint8_t *buffer, size_t buffer_size);

int psasim_serialise_buffer(uint8_t **pos, size_t *remaining, const uint8_t *buffer, size_t buffer_length);

int psasim_deserialise_buffer(uint8_t **pos, size_t *remaining, uint8_t **buffer, size_t *buffer_length);

// When client is deserialising a buffer returned from the server, it needs to use
// this for the returning buffer. (It uses the normal serialise_buffer() on the
// outbound call.)
int psasim_deserialise_return_buffer(uint8_t **pos, size_t *remaining, uint8_t *buffer, size_t buffer_length);

size_t psasim_serialise_psa_hash_operation_t_needs(psa_hash_operation_t value);

int psasim_serialise_psa_hash_operation_t(uint8_t **pos, size_t *remaining, psa_hash_operation_t value);

int psasim_deserialise_psa_hash_operation_t(uint8_t **pos, size_t *remaining, psa_hash_operation_t *value);
