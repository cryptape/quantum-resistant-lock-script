#include <stddef.h>
#include <stdint.h>

#include "params.h"

#define SPX_MLEN 32

uint32_t sphincs_plus_get_pk_size();
uint32_t sphincs_plus_get_sk_size();
uint32_t sphincs_plus_get_sign_size();

#ifndef CKB_VM
int sphincs_plus_generate_keypair(uint8_t *pk, uint8_t *sk);
int sphincs_plus_sign(uint8_t *message, uint8_t *sk, uint8_t *out_sign);
#endif  // !CKB_VM

int sphincs_plus_verify(uint8_t *sign, uint32_t sign_size, uint8_t *message,
                        uint32_t message_size, uint8_t *pubkey,
                        uint32_t pubkey_size);