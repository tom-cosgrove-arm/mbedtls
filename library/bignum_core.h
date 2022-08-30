/**
 *  Core bignum functions
 *
 *  This interface should only be used by the legacy bignum module (bignum.h)
 *  and the modular bignum modules (bignum_mod.c, bignum_mod_raw.c). All other
 *  modules should use the high-level modular bignum interface (bignum_mod.h)
 *  or the legacy bignum interface (bignum.h).
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef MBEDTLS_BIGNUM_CORE_H
#define MBEDTLS_BIGNUM_CORE_H

#include "common.h"

#if defined(MBEDTLS_BIGNUM_C)
#include "mbedtls/bignum.h"
#endif

/** Count leading zero bits in a given integer.
 *
 * \param a     Integer to count leading zero bits.
 *
 * \return      The number of leading zero bits in \p a.
 */
size_t mbedtls_mpi_core_clz( mbedtls_mpi_uint a );

/** Return the minimum number of bits required to represent the value held
 * in the MPI.
 *
 * \note This function returns 0 if all the limbs of \p A are 0.
 *
 * \param[in] A     The address of the MPI.
 * \param A_limbs   The number of limbs of \p A.
 *
 * \return      The number of bits in \p A.
 */
size_t mbedtls_mpi_core_bitlen( const mbedtls_mpi_uint *A, size_t A_limbs );

/** Convert a big-endian byte array aligned to the size of mbedtls_mpi_uint
 * into the storage form used by mbedtls_mpi.
 *
 * \param[in,out] A     The address of the MPI.
 * \param A_limbs       The number of limbs of \p A.
 */
void mbedtls_mpi_core_bigendian_to_host( mbedtls_mpi_uint *A,
                                         size_t A_limbs );

/** Import X from unsigned binary data, little-endian.
 *
 * The MPI needs to have enough limbs to store the full value (including any
 * most significant zero bytes in the input).
 *
 * \param[out] X         The address of the MPI.
 * \param X_limbs        The number of limbs of \p X.
 * \param[in] input      The input buffer to import from.
 * \param input_length   The length bytes of \p input.
 *
 * \return       \c 0 if successful.
 * \return       #MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL if \p X isn't
 *               large enough to hold the value in \p input.
 */
int mbedtls_mpi_core_read_le( mbedtls_mpi_uint *X,
                              size_t X_limbs,
                              const unsigned char *input,
                              size_t input_length );

/** Import X from unsigned binary data, big-endian.
 *
 * The MPI needs to have enough limbs to store the full value (including any
 * most significant zero bytes in the input).
 *
 * \param[out] X        The address of the MPI.
 *                      May only be #NULL if \X_limbs is 0 and \p input_length
 *                      is 0.
 * \param X_limbs       The number of limbs of \p X.
 * \param[in] input     The input buffer to import from.
 *                      May only be #NULL if \p input_length is 0.
 * \param input_length  The length in bytes of \p input.
 *
 * \return       \c 0 if successful.
 * \return       #MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL if \p X isn't
 *               large enough to hold the value in \p input.
 */
int mbedtls_mpi_core_read_be( mbedtls_mpi_uint *X,
                              size_t X_limbs,
                              const unsigned char *input,
                              size_t input_length );

/** Export A into unsigned binary data, little-endian.
 *
 * \note If \p output is shorter than \p A the export is still successful if the
 *       value held in \p A fits in the buffer (that is, if enough of the most
 *       significant bytes of \p A are 0).
 *
 * \param[in] A         The address of the MPI.
 * \param A_limbs       The number of limbs of \p A.
 * \param[out] output   The output buffer to export to.
 * \param output_length The length in bytes of \p output.
 *
 * \return       \c 0 if successful.
 * \return       #MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL if \p output isn't
 *               large enough to hold the value of \p A.
 */
int mbedtls_mpi_core_write_le( const mbedtls_mpi_uint *A,
                               size_t A_limbs,
                               unsigned char *output,
                               size_t output_length );

/** Export A into unsigned binary data, big-endian.
 *
 * \note If \p output is shorter than \p A the export is still successful if the
 *       value held in \p A fits in the buffer (that is, if enough of the most
 *       significant bytes of \p A are 0).
 *
 * \param[in] A         The address of the MPI.
 * \param A_limbs       The number of limbs of \p A.
 * \param[out] output   The output buffer to export to.
 * \param output_length The length in bytes of \p output.
 *
 * \return       \c 0 if successful.
 * \return       #MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL if \p output isn't
 *               large enough to hold the value of \p A.
 */
int mbedtls_mpi_core_write_be( const mbedtls_mpi_uint *A,
                               size_t A_limbs,
                               unsigned char *output,
                               size_t output_length );

#define ciL    ( sizeof(mbedtls_mpi_uint) )   /* chars in limb  */
#define biL    ( ciL << 3 )                   /* bits  in limb  */
#define biH    ( ciL << 2 )                   /* half limb size */

/*
 * Convert between bits/chars and number of limbs
 * Divide first in order to avoid potential overflows
 */
#define BITS_TO_LIMBS(i)  ( (i) / biL + ( (i) % biL != 0 ) )
#define CHARS_TO_LIMBS(i) ( (i) / ciL + ( (i) % ciL != 0 ) )
/* Get a specific byte, without range checks. */
#define GET_BYTE( X, i )                                \
    ( ( (X)[(i) / ciL] >> ( ( (i) % ciL ) * 8 ) ) & 0xff )

/**
 * \brief Conditional addition of two known-size large unsigned integers,
 *        returning the carry.
 *
 * Functionally equivalent to
 *
 * ```
 * if( cond )
 *    A += B;
 * return carry;
 * ```
 *
 * \param[in,out] A  The pointer to the (little-endian) array
 *                   representing the bignum to accumulate onto.
 * \param[in] B      The pointer to the (little-endian) array
 *                   representing the bignum to conditionally add
 *                   to \p A. This must be disjoint from \p A.
 * \param limbs      Number of limbs of \p A and \p B.
 * \param cond       Condition bit dictating whether addition should
 *                   happen or not. This must be \c 0 or \c 1.
 *
 * \warning          If \p cond is neither 0 nor 1, the result of this function
 *                   is unspecified, and the resulting value in \p A might be
 *                   neither its original value nor \p A + \p B.
 *
 * \return           1 if `A + cond * B >= (2^{ciL})^limbs`, 0 otherwise.
 */
mbedtls_mpi_uint mbedtls_mpi_core_add_if( mbedtls_mpi_uint *A,
                                          const mbedtls_mpi_uint *B,
                                          size_t limbs,
                                          unsigned cond );

/**
 * \brief Subtract two known-size large unsigned integers, returning the borrow.
 *
 * Calculate A - B where A and B have the same size.
 * This function operates modulo (2^ciL)^limbs and returns the carry
 * (1 if there was a wraparound, i.e. if `A < B`, and 0 otherwise).
 *
 * X may be aliased to A or B.
 *
 * \param[out] X    The result of the subtraction.
 * \param[in] A     Little-endian presentation of left operand.
 * \param[in] B     Little-endian presentation of right operand.
 * \param limbs     Number of limbs of \p X, \p A and \p B.
 *
 * \return          1 if `A < B`.
 *                  0 if `A >= B`.
 */
mbedtls_mpi_uint mbedtls_mpi_core_sub( mbedtls_mpi_uint *X,
                                       const mbedtls_mpi_uint *A,
                                       const mbedtls_mpi_uint *B,
                                       size_t limbs );

/**
 * \brief Perform a known-size multiply accumulate operation: A += c * B
 *
 * \param[in,out] A  The pointer to the (little-endian) array
 *                   representing the bignum to accumulate onto.
 * \param A_limbs    The number of limbs of \p A. This must be
 *                   at least \p B_limbs.
 * \param[in] B      The pointer to the (little-endian) array
 *                   representing the bignum to multiply with.
 *                   This may be the same as \p A. Otherwise,
 *                   it must be disjoint from \p A.
 * \param B_limbs    The number of limbs of \p B.
 * \param c          A scalar to multiply with.
 *
 * \return           The carry at the end of the operation.
 */
mbedtls_mpi_uint mbedtls_mpi_core_mla( mbedtls_mpi_uint *A, size_t A_limbs,
                                       const mbedtls_mpi_uint *B, size_t B_limbs,
                                       mbedtls_mpi_uint c );

/**
 * \brief Calculate initialisation value for fast Montgomery modular
 *        multiplication
 *
 * \param[in] N  Little-endian presentation of the modulus. This must have
 *               at least one limb.
 *
 * \return       The initialisation value for fast Montgomery modular multiplication
 */
mbedtls_mpi_uint mbedtls_mpi_montg_init( const mbedtls_mpi_uint *N );

/**
 * \brief Montgomery multiplication: X = A * B * R^-1 mod N  (HAC 14.36)
 *
 * \param[out]    X         The destination MPI, as a little-endian array of
 *                          length \p AN_limbs.
 *                          On successful completion, X contains the result of
 *                          the multiplication A * B * R^-1 mod N where
 *                          R = (2^ciL)^AN_limbs.
 * \param[in]     A         Little-endian presentation of first operand.
 *                          Must have exactly \p AN_limbs limbs.
 * \param[in]     B         Little-endian presentation of second operand.
 * \param[in]     B_limbs   The number of limbs in \p B.
 * \param[in]     N         Little-endian presentation of the modulus.
 *                          This must be odd and have exactly \p AN_limbs limbs.
 * \param[in]     AN_limbs  The number of limbs in \p X, \p A, \p N.
 * \param         mm        The Montgomery constant for \p N: -N^-1 mod 2^ciL.
 *                          This can be calculated by `mbedtls_mpi_montg_init()`.
 * \param[in,out] T         Temporary storage of size at least 2*AN_limbs+1 limbs.
 *                          Its initial content is unused and
 *                          its final content is indeterminate.
 */
void mbedtls_mpi_core_montmul( mbedtls_mpi_uint *X,
                               const mbedtls_mpi_uint *A,
                               const mbedtls_mpi_uint *B, size_t B_limbs,
                               const mbedtls_mpi_uint *N, size_t AN_limbs,
                               mbedtls_mpi_uint mm, mbedtls_mpi_uint *T );

#endif /* MBEDTLS_BIGNUM_CORE_H */
