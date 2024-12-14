#include "Crypto.h"

#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>

/*
 * Implement: Galois Field 2^16
 */
uint16_t gf_mul(uint16_t num_1, uint16_t num_2) {
    uint16_t result = 0;
    for (; num_2; num_2 >>= 1) {
        if (num_2 & 1)
            result ^= num_1;
        if (num_1 & 0x8000)
            num_1 = (num_1 << 1) ^ PRIMITIVE_POLY;
        else
            num_1 <<= 1;
    }
    return result;
}

uint16_t gf_pow(uint16_t num_base, uint16_t num_exp) {
    uint16_t result = 1;
    while (num_exp > 0) {
        if (num_exp % 2 == 1) {
            result = gf_mul(result, num_base);
        }
        num_base = gf_mul(num_base, num_base);
        num_exp /= 2;
    }
    return result;
}

/*
 * Implement: Block Cipher
 */
typedef uint16_t state_t[4];
uint8_t*  bits = NULL;
uint16_t* sbox = NULL;

void init_sbox() {
    sbox = mmap(0, 1<<24, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (sbox == MAP_FAILED) {
        perror("mmap failed :<");
        exit(1);
    }
    for (size_t i=0; i<0x10000; ++i) sbox[i] = gf_pow(i, 3) ^ 3;
}

static void key_expansion(uint16_t* rkeys, uint8_t* master_key) {
    for (int i=0; i<KEY_SIZE/2; ++i)
        rkeys[i] = (master_key[2*i+1] << 8) | master_key[2*i];
}

void Cipher_init_ctx(struct Cipher_ctx* ctx, uint8_t* master_key) {
    if (sbox == NULL) init_sbox();
    key_expansion(ctx->rkeys, master_key);
}

void Cipher(state_t* state, const uint16_t* rkeys) {
    for (int r=0; r<NUM_ROUNDS; ++r) {
        for (int i=0; i<4; ++i)
            (*state)[i] ^= sbox[(*state)[(i + 1)%4] ^ rkeys[i + r*4]];
    }
}

void InvCipher(state_t* state, const uint16_t* rkeys) {
    for (int r=NUM_ROUNDS-1; r>=0; --r) {
        for (int i=4-1; i>=0; --i)
            (*state)[i] ^= sbox[(*state)[(i + 1)%4] ^ rkeys[i + r*4]];
    }
}

void Cipher_ECB_encrypt(const struct Cipher_ctx* ctx, uint8_t* buffer) {
    Cipher((state_t*)buffer, ctx->rkeys);
}

void Cipher_ECB_decrypt(const struct Cipher_ctx* ctx, uint8_t* buffer) {
    InvCipher((state_t*)buffer, ctx->rkeys);
}

void Cipher_get_token(const struct Cipher_ctx* ctx, uint8_t* buffer) {
    if (bits == NULL) {
        bits = mmap(0, 1<<24, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (bits == MAP_FAILED) {
            perror("mmap failed :<");
            exit(1);
        }

        for (size_t i=0; i<0x80; ++i) bits[i] = 1;  // exactly 128 bit is set
    }

    uint8_t* key = malloc(0x18);
    int       fd = open("/dev/urandom", O_RDONLY);
    read(fd, key, 0x18);
    close(fd);

    // shuffling bits using RC4 KSA algorithm
    size_t i, j=0, t;
    for (i=0; i<0x100; ++i) {
        j = (j + bits[i] + key[i%0x18]) & 0xff;
        t = bits[i];
        bits[i] = bits[j];
        bits[j] = t;
    }

    for (i=0; i<0x20; ++i) {
        uint8_t r=0;
        for (j=0; j<8; ++j)
            r |= (bits[i*8+j] << j);
        buffer[i] ^= r;
    }

    for (size_t i=0; i<0x20; i+=BLOCK_SIZE)
        Cipher_ECB_decrypt(ctx, buffer+i);
}