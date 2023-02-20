#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "address.h"
#include "api.h"
#include "fors.h"
#include "hash.h"
#include "merkle.h"
#include "params.h"
#include "randombytes.h"
#include "thash.h"
#include "utils.h"
#include "wots.h"

#define SPX_CTX_SHA2_STATE_SEEDED_SIZE 40
#define SPX_CTX_SHA2_STATE_SEEDED_512_SIZE 72
#define SPX_CTX_HARAKA_TWEAKED512_RC64_SIZE 8 * 10 * 8
#define SPX_CTX_HARAKA_TWEAKED256_RC32_SIZE 4 * 10 * 8

static size_t get_spx_ctx_buf_len(crypto_context *cctx) {
  size_t len = SPX_N + SPX_N;
  if (cctx->hash_type == CRYPTO_HASH_TYPE_SHA2) {
    len += SPX_CTX_SHA2_STATE_SEEDED_SIZE;
  } else if (cctx->hash_type == CRYPTO_HASH_TYPE_HARAKA) {
    len += SPX_CTX_HARAKA_TWEAKED512_RC64_SIZE;
    len += SPX_CTX_HARAKA_TWEAKED256_RC32_SIZE;
  }
  if (cctx->spx_sha512 == 1) {
    len += SPX_CTX_SHA2_STATE_SEEDED_512_SIZE;
  }
  return len;
}

void init_spx_ctx(crypto_context *cctx, spx_ctx *ctx, uint8_t *buffer,
                  size_t buffer_len) {
  ASSERT(buffer_len >= get_spx_ctx_buf_len(cctx));
  ctx->pub_seed = buffer;
  buffer += SPX_N;
  ctx->sk_seed = buffer;
  buffer += SPX_N;

  if (cctx->hash_type == CRYPTO_HASH_TYPE_SHA2) {
    ctx->state_seeded = buffer;
    buffer += SPX_CTX_SHA2_STATE_SEEDED_SIZE;
  } else if (cctx->hash_type == CRYPTO_HASH_TYPE_HARAKA) {
    ctx->tweaked512_rc64 = (uint64_t *)buffer;
    buffer += SPX_CTX_HARAKA_TWEAKED512_RC64_SIZE;
    ctx->tweaked256_rc32 = (uint32_t *)buffer;
    buffer += SPX_CTX_HARAKA_TWEAKED256_RC32_SIZE;
  }
  if (cctx->spx_sha512 == 1) {
    ctx->state_seeded_512 = buffer;
    buffer += SPX_CTX_SHA2_STATE_SEEDED_512_SIZE;
  }
}

#define INIT_SPX_CTX                          \
  spx_ctx ctx;                                \
  uint8_t ctx_buf[get_spx_ctx_buf_len(cctx)]; \
  init_spx_ctx(cctx, &ctx, ctx_buf, sizeof(ctx_buf));

/*
 * Returns the length of a secret key, in bytes
 */
unsigned long long crypto_sign_secretkeybytes(crypto_context *cctx) {
  return CRYPTO_SECRETKEYBYTES;
}

/*
 * Returns the length of a public key, in bytes
 */
unsigned long long crypto_sign_publickeybytes(crypto_context *cctx) {
  return CRYPTO_PUBLICKEYBYTES;
}

/*
 * Returns the length of a signature, in bytes
 */
unsigned long long crypto_sign_bytes(crypto_context *cctx) {
  return CRYPTO_BYTES;
}

/*
 * Returns the length of the seed required to generate a key pair, in bytes
 */
unsigned long long crypto_sign_seedbytes(crypto_context *cctx) {
  return CRYPTO_SEEDBYTES;
}

/*
 * Generates an SPX key pair given a seed of length
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */
int crypto_sign_seed_keypair(crypto_context *cctx, unsigned char *pk,
                             unsigned char *sk, const unsigned char *seed) {
  INIT_SPX_CTX;

  /* Initialize SK_SEED, SK_PRF and PUB_SEED from seed. */
  memcpy(sk, seed, CRYPTO_SEEDBYTES);

  memcpy(pk, sk + 2 * SPX_N, SPX_N);

  memcpy(ctx.pub_seed, pk, SPX_N);
  memcpy(ctx.sk_seed, sk, SPX_N);

  /* This hook allows the hash function instantiation to do whatever
     preparation or computation it needs, based on the public seed. */
  initialize_hash_function(cctx, &ctx);

  /* Compute root node of the top-most subtree. */
  merkle_gen_root(cctx, sk + 3 * SPX_N, &ctx);

  memcpy(pk + SPX_N, sk + 3 * SPX_N, SPX_N);

  return 0;
}

/*
 * Generates an SPX key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */
int crypto_sign_keypair(crypto_context *cctx, unsigned char *pk,
                        unsigned char *sk) {
  unsigned char seed[CRYPTO_SEEDBYTES];
  randombytes(seed, CRYPTO_SEEDBYTES);
  crypto_sign_seed_keypair(cctx, pk, sk, seed);

  return 0;
}

/**
 * Returns an array containing a detached signature.
 */
int crypto_sign_signature(crypto_context *cctx, uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen, const uint8_t *sk) {
  INIT_SPX_CTX;

  const unsigned char *sk_prf = sk + SPX_N;
  const unsigned char *pk = sk + 2 * SPX_N;

  unsigned char optrand[SPX_N];
  unsigned char mhash[SPX_FORS_MSG_BYTES];
  unsigned char root[SPX_N];
  uint32_t i;
  uint64_t tree;
  uint32_t idx_leaf;
  uint32_t wots_addr[8] = {0};
  uint32_t tree_addr[8] = {0};

  memcpy(ctx.sk_seed, sk, SPX_N);
  memcpy(ctx.pub_seed, pk, SPX_N);

  /* This hook allows the hash function instantiation to do whatever
     preparation or computation it needs, based on the public seed. */
  initialize_hash_function(cctx, &ctx);

  set_type(cctx, wots_addr, SPX_ADDR_TYPE_WOTS);
  set_type(cctx, tree_addr, SPX_ADDR_TYPE_HASHTREE);

  /* Optionally, signing can be made non-deterministic using optrand.
     This can help counter side-channel attacks that would benefit from
     getting a large number of traces when the signer uses the same nodes. */
  randombytes(optrand, SPX_N);
  /* Compute the digest randomization value. */
  gen_message_random(cctx, sig, sk_prf, optrand, m, mlen, &ctx);

  /* Derive the message digest and leaf index from R, PK and M. */
  hash_message(cctx, mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
  sig += SPX_N;

  set_tree_addr(cctx, wots_addr, tree);
  set_keypair_addr(cctx, wots_addr, idx_leaf);

  /* Sign the message hash using FORS. */
  fors_sign(cctx, sig, root, mhash, &ctx, wots_addr);
  sig += SPX_FORS_BYTES;

  for (i = 0; i < SPX_D; i++) {
    set_layer_addr(cctx, tree_addr, i);
    set_tree_addr(cctx, tree_addr, tree);

    copy_subtree_addr(cctx, wots_addr, tree_addr);
    set_keypair_addr(cctx, wots_addr, idx_leaf);

    merkle_sign(cctx, sig, root, &ctx, wots_addr, tree_addr, idx_leaf);
    sig += SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N;

    /* Update the indices for the next layer. */
    idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1));
    tree = tree >> SPX_TREE_HEIGHT;
  }

  *siglen = SPX_BYTES;

  return 0;
}

/**
 * Verifies a detached signature and message under a given public key.
 */
int crypto_sign_verify(crypto_context *cctx, const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen, const uint8_t *pk) {
  INIT_SPX_CTX;

  const unsigned char *pub_root = pk + SPX_N;
  unsigned char mhash[SPX_FORS_MSG_BYTES];
  unsigned char wots_pk[SPX_WOTS_BYTES];
  unsigned char root[SPX_N];
  unsigned char leaf[SPX_N];
  unsigned int i;
  uint64_t tree;
  uint32_t idx_leaf;
  uint32_t wots_addr[8] = {0};
  uint32_t tree_addr[8] = {0};
  uint32_t wots_pk_addr[8] = {0};

  if (siglen != SPX_BYTES) {
    return -1;
  }

  memcpy(ctx.pub_seed, pk, SPX_N);

  /* This hook allows the hash function instantiation to do whatever
     preparation or computation it needs, based on the public seed. */
  initialize_hash_function(cctx, &ctx);

  set_type(cctx, wots_addr, SPX_ADDR_TYPE_WOTS);
  set_type(cctx, tree_addr, SPX_ADDR_TYPE_HASHTREE);
  set_type(cctx, wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

  /* Derive the message digest and leaf index from R || PK || M. */
  /* The additional SPX_N is a result of the hash domain separator. */
  hash_message(cctx, mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
  sig += SPX_N;

  /* Layer correctly defaults to 0, so no need to set_layer_addr */
  set_tree_addr(cctx, wots_addr, tree);
  set_keypair_addr(cctx, wots_addr, idx_leaf);

  fors_pk_from_sig(cctx, root, sig, mhash, &ctx, wots_addr);
  sig += SPX_FORS_BYTES;

  /* For each subtree.. */
  for (i = 0; i < SPX_D; i++) {
    set_layer_addr(cctx, tree_addr, i);
    set_tree_addr(cctx, tree_addr, tree);

    copy_subtree_addr(cctx, wots_addr, tree_addr);
    set_keypair_addr(cctx, wots_addr, idx_leaf);

    copy_keypair_addr(cctx, wots_pk_addr, wots_addr);

    /* The WOTS public key is only correct if the signature was correct. */
    /* Initially, root is the FORS pk, but on subsequent iterations it is
       the root of the subtree below the currently processed subtree. */
    wots_pk_from_sig(cctx, wots_pk, sig, root, &ctx, wots_addr);
    sig += SPX_WOTS_BYTES;

    /* Compute the leaf node using the WOTS public key. */
    thash(cctx, leaf, wots_pk, SPX_WOTS_LEN, &ctx, wots_pk_addr);

    /* Compute the root node of this subtree. */
    compute_root(cctx, root, leaf, idx_leaf, 0, sig, SPX_TREE_HEIGHT, &ctx,
                 tree_addr);
    sig += SPX_TREE_HEIGHT * SPX_N;

    /* Update the indices for the next layer. */
    idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1));
    tree = tree >> SPX_TREE_HEIGHT;
  }

  /* Check if the root node equals the root node in the public key. */
  if (memcmp(root, pub_root, SPX_N)) {
    return -1;
  }

  return 0;
}

/**
 * Returns an array containing the signature followed by the message.
 */
int crypto_sign(crypto_context *cctx, unsigned char *sm,
                unsigned long long *smlen, const unsigned char *m,
                unsigned long long mlen, const unsigned char *sk) {
  size_t siglen;

  crypto_sign_signature(cctx, sm, &siglen, m, (size_t)mlen, sk);

  memmove(sm + SPX_BYTES, m, mlen);
  *smlen = siglen + mlen;

  return 0;
}

/**
 * Verifies a given signature-message pair under a given public key.
 */
int crypto_sign_open(crypto_context *cctx, unsigned char *m,
                     unsigned long long *mlen, const unsigned char *sm,
                     unsigned long long smlen, const unsigned char *pk) {
  /* The API caller does not necessarily know what size a signature should be
     but SPHINCS+ signatures are always exactly SPX_BYTES. */
  if (smlen < SPX_BYTES) {
    memset(m, 0, smlen);
    *mlen = 0;
    return -1;
  }

  *mlen = smlen - SPX_BYTES;

  if (crypto_sign_verify(cctx, sm, SPX_BYTES, sm + SPX_BYTES, (size_t)*mlen,
                         pk)) {
    memset(m, 0, smlen);
    *mlen = 0;
    return -1;
  }

  /* If verification was successful, move the message to the right place. */
  memmove(m, sm + SPX_BYTES, *mlen);

  return 0;
}
