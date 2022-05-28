/**
 * \file aes.h
 * \brief Header defining the API for OQS AES
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef OQS_AES_H
#define OQS_AES_H

#include <stdint.h>
#include <stdlib.h>

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * Function to fill a key schedule given an initial key for use in ECB mode.
 *
 * @param key            Initial Key.
 * @param schedule       Abstract data structure for a key schedule.
 */
void OQS_AES128_ECB_load_schedule(const uint8_t *key, void **schedule);

/**
 * Function to free a key schedule.
 *
 * @param schedule       Schedule generated with OQS_AES128_ECB_load_schedule().
 */
void OQS_AES128_free_schedule(void *schedule);

/**
 * Function to encrypt blocks of plaintext using ECB mode.
 * A schedule based on the key is generated and used internally.
 *
 * @param plaintext     Plaintext to be encrypted.
 * @param plaintext_len Length on the plaintext in bytes. Must be a multiple of 16.
 * @param key           Key to be used for encryption.
 * @param ciphertext    Pointer to a block of memory which >= in size to the plaintext block. The result will be written here.
 * @warning plaintext_len must be a multiple of 16.
 */
void OQS_AES128_ECB_enc(const uint8_t *plaintext, const size_t plaintext_len, const uint8_t *key, uint8_t *ciphertext);

/**
 * Same as OQS_AES128_ECB_enc() except a schedule generated by
 * OQS_AES128_ECB_load_schedule() is passed rather then a key. This is faster
 * if the same schedule is used for multiple encryptions since it does
 * not have to be regenerated from the key.
 */
void OQS_AES128_ECB_enc_sch(const uint8_t *plaintext, const size_t plaintext_len, const void *schedule, uint8_t *ciphertext);

/**
 * Function to fill a key schedule given an initial key for use in ECB mode encryption.
 *
 * @param key            Initial Key.
 * @param schedule       Abstract data structure for a key schedule.
 */
void OQS_AES256_ECB_load_schedule(const uint8_t *key, void **schedule);

/**
 * Function to fill a key schedule given an initial key for use in CTR mode.
 *
 * @param key            Initial Key.
 * @param schedule       Abstract data structure for a key schedule.
 */
void OQS_AES256_CTR_load_schedule(const uint8_t *key, void **schedule);

/**
 * Function to free a key schedule.
 *
 * @param schedule       Schedule generated with OQS_AES256_ECB_load_schedule
 *                       or OQS_AES256_CTR_load_schedule.
 */
void OQS_AES256_free_schedule(void *schedule);

/**
 * Function to encrypt blocks of plaintext using ECB mode.
 * A schedule based on the key is generated and used internally.
 *
 * @param plaintext     Plaintext to be encrypted.
 * @param plaintext_len Length on the plaintext in bytes. Must be a multiple of 16.
 * @param key           Key to be used for encryption.
 * @param ciphertext    Pointer to a block of memory which >= in size to the plaintext block. The result will be written here.
 * @warning plaintext_len must be a multiple of 16.
 */
void OQS_AES256_ECB_enc(const uint8_t *plaintext, const size_t plaintext_len, const uint8_t *key, uint8_t *ciphertext);

/**
 * Same as OQS_AES256_ECB_enc() except a schedule generated by
 * OQS_AES256_ECB_load_schedule() is passed rather then a key. This is faster
 * if the same schedule is used for multiple encryptions since it does
 * not have to be regenerated from the key.
 */
void OQS_AES256_ECB_enc_sch(const uint8_t *plaintext, const size_t plaintext_len, const void *schedule, uint8_t *ciphertext);

/**
 * AES counter mode keystream generator.  A scheduled generated by
 * OQS_AES256_CTR_load_schedule() is passed rather then a key.
 *
 * Handles a 12- or 16-byte IV.  If a 12-byte IV is given, then 4 counter
 * bytes are initialized to all zeros.
 *
 * @param iv       12- or 16-byte initialization vector.
 * @param iv_len   Lengh of IV in bytes.
 * @param schedule Abstract data structure for a key schedule.
 * @param out      Pointer to a block of memory which is big enough to contain out_len bytes; the result will be written here.
 * @param out_len  Length of output bytes to generate.
 */
void OQS_AES256_CTR_sch(const uint8_t *iv, size_t iv_len, const void *schedule, uint8_t *out, size_t out_len);

#if defined(__cplusplus)
} // extern "C"
#endif

#endif // OQS_AES_H