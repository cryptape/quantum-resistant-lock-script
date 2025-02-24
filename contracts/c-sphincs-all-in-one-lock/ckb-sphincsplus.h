#include <stddef.h>
#include <stdint.h>

#include "params.h"

#define SPX_MLEN 32

#define SPHINCS_PLUS_PK_SIZE SPX_PK_BYTES
#define SPHINCS_PLUS_SK_SIZE SPX_SK_BYTES
#define SPHINCS_PLUS_SIGN_SIZE (SPX_BYTES + SPX_MLEN)

#ifndef CKB_VM
int sphincs_plus_generate_keypair(uint8_t *pk, uint8_t *sk);
int sphincs_plus_sign(const uint8_t *message, const uint8_t *sk,
                      uint8_t *out_sign);
#endif  // !CKB_VM

int sphincs_plus_verify(const uint8_t *sign, uint32_t sign_size,
                        const uint8_t *message, uint32_t message_size,
                        const uint8_t *pubkey, uint32_t pubkey_size);
