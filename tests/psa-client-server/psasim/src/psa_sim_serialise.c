/**
 * \file psa_sim_serialise.c
 *
 * \brief Rough-and-ready serialisation and deserialisation for the PSA Crypto simulator
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "psa_sim_serialise.h"
#include <stdlib.h>
#include <string.h>

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

size_t psasim_serialise_begin_needs(void)
{
    // Buffer will start with a byte of 0 to indicate version 0,
    // then have 1 byte each for length of int, long, void *,
    // then have 4 bytes to indicate endianness.
    return 4 + sizeof(uint32_t);
}

int psasim_serialise_begin(uint8_t **pos, size_t *remaining)
{
    uint32_t endian = 0x1234;

    if (*remaining < 4 + sizeof(endian)) {
        return 0;
    }

    *(*pos)++ = 0;      /* version */
    *(*pos)++ = (uint8_t)sizeof(int);
    *(*pos)++ = (uint8_t)sizeof(long);
    *(*pos)++ = (uint8_t)sizeof(void *);

    memcpy(*pos, &endian, sizeof(endian));

    *pos += sizeof(endian);

    return 1;
}

int psasim_deserialise_begin(uint8_t **pos, size_t *remaining)
{
    uint8_t version = 255;
    uint8_t int_size = 0;
    uint8_t long_size = 0;
    uint8_t ptr_size = 0;
    uint32_t endian;

    if (*remaining < 4 + sizeof(endian)) {
        return 0;
    }

    memcpy(&version, (*pos)++, sizeof(version));
    if (version != 0) {
        return 0;
    }

    memcpy(&int_size, (*pos)++, sizeof(int_size));
    if (int_size != sizeof(int)) {
        return 0;
    }

    memcpy(&long_size, (*pos)++, sizeof(long_size));
    if (long_size != sizeof(long)) {
        return 0;
    }

    memcpy(&ptr_size, (*pos)++, sizeof(ptr_size));
    if (ptr_size != sizeof(void *)) {
        return 0;
    }

    *remaining -= 4;

    memcpy(&endian, *pos, sizeof(endian));
    if (endian != 0x1234) {
        return 0;
    }

    *pos += sizeof(endian);
    *remaining -= sizeof(endian);

    return 1;
}

size_t psasim_serialise_unsigned_int_needs(unsigned int value)
{
    return sizeof(value);
}

int psasim_serialise_unsigned_int(uint8_t **pos, size_t *remaining, unsigned int value)
{
    if (*remaining < sizeof(value)) {
        return 0;
    }

    memcpy(*pos, &value, sizeof(value));
    *pos += sizeof(value);

    return 1;
}

int psasim_deserialise_unsigned_int(uint8_t **pos, size_t *remaining, unsigned int *value)
{
    if (*remaining < sizeof(*value)) {
        return 0;
    }

    memcpy(value, *pos, sizeof(*value));

    *pos += sizeof(*value);
    *remaining -= sizeof(*value);

    return 1;
}

size_t psasim_serialise_int_needs(int value)
{
    return sizeof(value);
}

int psasim_serialise_int(uint8_t **pos, size_t *remaining, int value)
{
    if (*remaining < sizeof(value)) {
        return 0;
    }

    memcpy(*pos, &value, sizeof(value));
    *pos += sizeof(value);

    return 1;
}

int psasim_deserialise_int(uint8_t **pos, size_t *remaining, int *value)
{
    if (*remaining < sizeof(value)) {
        return 0;
    }

    memcpy(value, *pos, sizeof(*value));

    *pos += sizeof(*value);
    *remaining -= sizeof(*value);

    return 1;
}

size_t psasim_serialise_psa_status_t_needs(int value)
{
    return psasim_serialise_int_needs(value);
}

int psasim_serialise_psa_status_t(uint8_t **pos, size_t *remaining, int value)
{
    return psasim_serialise_int(pos, remaining, value);
}

int psasim_deserialise_psa_status_t(uint8_t **pos, size_t *remaining, int *value)
{
    return psasim_deserialise_int(pos, remaining, value);
}

size_t psasim_serialise_psa_algorithm_t_needs(psa_algorithm_t value)
{
    return psasim_serialise_unsigned_int_needs(value);
}

int psasim_serialise_psa_algorithm_t(uint8_t **pos, size_t *remaining, psa_algorithm_t value)
{
    return psasim_serialise_unsigned_int(pos, remaining, value);
}

int psasim_deserialise_psa_algorithm_t(uint8_t **pos, size_t *remaining, psa_algorithm_t *value)
{
    return psasim_deserialise_unsigned_int(pos, remaining, value);
}

size_t psasim_serialise_size_t_needs(size_t value)
{
    return sizeof(value);
}

int psasim_serialise_size_t(uint8_t **pos, size_t *remaining, size_t value)
{
    if (*remaining < sizeof(value)) {
        return 0;
    }

    memcpy(*pos, &value, sizeof(value));
    *pos += sizeof(value);

    return 1;
}

int psasim_deserialise_size_t(uint8_t **pos, size_t *remaining, size_t *value)
{
    if (*remaining < sizeof(value)) {
        return 0;
    }

    memcpy(value, *pos, sizeof(*value));

    *pos += sizeof(value);
    *remaining -= sizeof(value);

    return 1;
}

size_t psasim_serialise_buffer_needs(const uint8_t *buffer, size_t buffer_size)
{
    (void)buffer;
    return sizeof(buffer_size) + buffer_size;
}

int psasim_serialise_buffer(uint8_t **pos, size_t *remaining, const uint8_t *buffer, size_t buffer_length)
{
    if (*remaining < sizeof(buffer_length) + buffer_length) {
        return 0;
    }

    memcpy(*pos, &buffer_length, sizeof(buffer_length));
    *pos += sizeof(buffer_length);

    if (buffer_length > 0) {    // To be able to serialise (NULL, 0)
        memcpy(*pos, buffer, buffer_length);
        *pos += buffer_length;
    }

    return 1;
}

int psasim_deserialise_buffer(uint8_t **pos, size_t *remaining, uint8_t **buffer, size_t *buffer_length)
{
    if (*remaining < sizeof(*buffer_length)) {
        return 0;
    }

    memcpy(buffer_length, *pos, sizeof(*buffer_length));

    *pos += sizeof(buffer_length);
    *remaining -= sizeof(buffer_length);

    if (*buffer_length == 0) {          // Deserialise (NULL, 0)
        *buffer = NULL;
        return 1;
    }

    if (*remaining < *buffer_length) {
        return 0;
    }

    uint8_t *data = malloc(*buffer_length);
    if (data == NULL) {
        return 0;
    }

    memcpy(data, *pos, *buffer_length);
    *pos += *buffer_length;
    *remaining -= *buffer_length;

    *buffer = data;

    return 1;
}

// When client is deserialising a buffer returned from the server, it needs to use
// this for the returning buffer. (It uses the normal serialise_buffer() on the
// outbound call.)
int psasim_deserialise_return_buffer(uint8_t **pos, size_t *remaining, uint8_t *buffer, size_t buffer_length)
{
    if (*remaining < sizeof(buffer_length)) {
        return 0;
    }

    size_t length_check;

    memcpy(&length_check, *pos, sizeof(buffer_length));

    *pos += sizeof(buffer_length);
    *remaining -= sizeof(buffer_length);

    if (buffer_length != length_check) {        // Make sure we're sent back the same we sent to the server
        return 0;
    }

    if (length_check == 0) {          // Deserialise (NULL, 0)
        return 1;
    }

    if (*remaining < buffer_length) {
        return 0;
    }

    memcpy(buffer, *pos, buffer_length);
    *pos += buffer_length;
    *remaining -= buffer_length;

    return 1;
}

size_t psasim_serialise_psa_hash_operation_t_needs(psa_hash_operation_t value)
{
    return sizeof(value);
}

int psasim_serialise_psa_hash_operation_t(uint8_t **pos, size_t *remaining, psa_hash_operation_t value)
{
    if (*remaining < sizeof(value)) {
        return 0;
    }

    memcpy(*pos, &value, sizeof(value));
    *pos += sizeof(value);

    return 1;
}

int psasim_deserialise_psa_hash_operation_t(uint8_t **pos, size_t *remaining, psa_hash_operation_t *value)
{
    if (*remaining < sizeof(value)) {
        return 0;
    }

    memcpy(value, *pos, sizeof(*value));

    *pos += sizeof(*value);
    *remaining -= sizeof(*value);

    return 1;
}
