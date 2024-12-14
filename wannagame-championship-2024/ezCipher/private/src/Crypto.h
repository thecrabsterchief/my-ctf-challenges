#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <stdint.h>

#define PRIMITIVE_POLY 0x15A55
#define BLOCK_SIZE     0x08
#define NUM_ROUNDS     0x04
#define KEY_SIZE       0x20

/*
 * Define: Galois Field
 */
uint16_t gf_mul(uint16_t num_1   , uint16_t num_2  );
uint16_t gf_pow(uint16_t num_base, uint16_t num_exp);

/*
 * Define: Block Cipher
 */
struct Cipher_ctx {
    uint16_t rkeys[KEY_SIZE/2];
};

void Cipher_init_ctx(struct Cipher_ctx* ctx, uint8_t* master_key);
void Cipher_get_token(const struct Cipher_ctx* ctx, uint8_t* buffer);
void Cipher_ECB_encrypt(const struct Cipher_ctx* ctx, uint8_t* buffer);
void Cipher_ECB_decrypt(const struct Cipher_ctx* ctx, uint8_t* buffer);

#endif // __CRYPTO_H__