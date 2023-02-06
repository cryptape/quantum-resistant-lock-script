#include <stddef.h>
#include <stdint.h>

#include "params.h"

#define SPX_MLEN 32

uint32_t get_pk_size();
uint32_t get_sk_size();
uint32_t get_sign_size();

#ifndef CKB_VM
int sphincs_plus_generate_keypair(uint8_t *pk, uint8_t *sk);
int sphincs_plus_sign(uint8_t *message, uint8_t *sk, uint8_t *out_sign,
                      size_t *out_sign_len);
#endif  // CKB_VM
int sphincs_plus_verify(uint8_t *sign, size_t sign_len, uint8_t *message,
                        uint8_t *pubkey);