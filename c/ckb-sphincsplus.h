#include <stddef.h>
#include <stdint.h>

#include "params.h"

#define SPX_MLEN 32

#ifndef CKB_VM

crypto_context *sphincs_plus_new_context(crypto_type type);
void sphincs_plus_del_context(crypto_context *cctx);

#endif  // CKB_VM

uint32_t sphincs_plus_get_pk_size(crypto_context *cctx);
uint32_t sphincs_plus_get_sk_size(crypto_context *cctx);
uint32_t sphincs_plus_get_sign_size(crypto_context *cctx);

int sphincs_plus_init_context(crypto_type type, crypto_context *cctx);

#ifndef CKB_VM
int sphincs_plus_generate_keypair(crypto_context *cctx, uint8_t *pk,
                                  uint8_t *sk);
int sphincs_plus_sign(crypto_context *cctx, uint8_t *message, uint8_t *sk,
                      uint8_t *out_sign);
#endif  // !CKB_VM

int sphincs_plus_verify(crypto_context *cctx, uint8_t *sign, uint32_t sign_size,
                        uint8_t *message, uint32_t message_size,
                        uint8_t *pubkey, uint32_t pubkey_size);