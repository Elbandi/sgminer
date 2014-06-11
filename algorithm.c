/*
 * Copyright 2014 sgminer developers
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or (at
 * your option) any later version.  See COPYING for more details.
 */

#include "algorithm.h"
#include "scrypt.h"
#include "scrypt-jane.h"
#include "sha2.h"
#include "ocl.h"

#include "algorithm/scrypt.h"
#include "algorithm/animecoin.h"
#include "algorithm/inkcoin.h"
#include "algorithm/quarkcoin.h"
#include "algorithm/qubitcoin.h"
#include "algorithm/sifcoin.h"
#include "algorithm/darkcoin.h"
#include "algorithm/myriadcoin-groestl.h"
#include "algorithm/fuguecoin.h"
#include "algorithm/groestlcoin.h"
#include "algorithm/twecoin.h"
#include "algorithm/marucoin.h"
#include "algorithm/maxcoin.h"

#include "compat.h"

#include <inttypes.h>
#include <string.h>

void gen_hash(const unsigned char *data, unsigned int len, unsigned char *hash)
{
    unsigned char hash1[32];

    sha256(data, len, hash1);
    sha256(hash1, 32, hash);
}

#define CL_SET_BLKARG(blkvar) status |= clSetKernelArg(*kernel, num++, sizeof(uint), (void *)&blk->blkvar)
#define CL_SET_ARG(var) status |= clSetKernelArg(*kernel, num++, sizeof(var), (void *)&var)
#define CL_SET_VARG(args, var) status |= clSetKernelArg(*kernel, num++, args * sizeof(uint), (void *)var)
#define CL_SET_ARG_N(n,var) status |= clSetKernelArg(*kernel, n, sizeof(var), (void *)&var)
#define CL_SET_ARG_0(var) status |= clSetKernelArg(*kernel, 0, sizeof(var), (void *)&var)
#define CL_NEXTKERNEL_SET_ARG(var) kernel++; status |= clSetKernelArg(*kernel, num++, sizeof(var), (void *)&var)
#define CL_NEXTKERNEL_SET_ARG_0(var) kernel++; status |= clSetKernelArg(*kernel, 0, sizeof(var), (void *)&var)
#define CL_NEXTKERNEL_SET_ARG_N(n,var) kernel++; status |= clSetKernelArg(*kernel, n, sizeof(var), (void *)&var)

static cl_int queue_scrypt_kernel(struct __clState *clState, struct _dev_blk_ctx *blk, __maybe_unused cl_uint threads)
{
    unsigned char *midstate = blk->work->midstate;
    cl_kernel *kernel = &clState->kernel;
    unsigned int num = 0;
    cl_uint le_target;
    cl_int status = 0;

    le_target = *(cl_uint *)(blk->work->device_target + 28);
    memcpy(clState->cldata, blk->work->data, 80);
    status = clEnqueueWriteBuffer(clState->commandQueue, clState->CLbuffer0, true, 0, 80, clState->cldata, 0, NULL,NULL);

    CL_SET_ARG(clState->CLbuffer0);
    CL_SET_ARG(clState->outputBuffer);
    CL_SET_ARG(clState->padbuffer8);
    CL_SET_VARG(4, &midstate[0]);
    CL_SET_VARG(4, &midstate[16]);
    CL_SET_ARG(le_target);

    return status;
}

static cl_int queue_maxcoin_kernel(struct __clState *clState, struct _dev_blk_ctx *blk, __maybe_unused cl_uint threads)
{
    cl_kernel *kernel = &clState->kernel;
    unsigned int num = 0;
    cl_int status = 0;

    flip80(clState->cldata, blk->work->data);
    status = clEnqueueWriteBuffer(clState->commandQueue, clState->CLbuffer0, true, 0, 80, clState->cldata, 0, NULL,NULL);

    CL_SET_ARG(clState->CLbuffer0);
    CL_SET_ARG(clState->outputBuffer);

    return status;
}

static cl_int queue_sph_kernel(struct __clState *clState, struct _dev_blk_ctx *blk, __maybe_unused cl_uint threads)
{
    cl_kernel *kernel = &clState->kernel;
    unsigned int num = 0;
    cl_ulong le_target;
    cl_int status = 0;

    le_target = *(cl_ulong *)(blk->work->device_target + 24);
    flip80(clState->cldata, blk->work->data);
    status = clEnqueueWriteBuffer(clState->commandQueue, clState->CLbuffer0, true, 0, 80, clState->cldata, 0, NULL,NULL);

    CL_SET_ARG(clState->CLbuffer0);
    CL_SET_ARG(clState->outputBuffer);
    CL_SET_ARG(le_target);

    return status;
}

static cl_int queue_darkcoin_mod_kernel(struct __clState *clState, struct _dev_blk_ctx *blk, __maybe_unused cl_uint threads)
{
  cl_kernel *kernel;
  unsigned int num;
  cl_ulong le_target;
  cl_int status = 0;

  le_target = *(cl_ulong *)(blk->work->device_target + 24);
  flip80(clState->cldata, blk->work->data);
  status = clEnqueueWriteBuffer(clState->commandQueue, clState->CLbuffer0, true, 0, 80, clState->cldata, 0, NULL,NULL);

  // blake - search
  kernel = &clState->kernel;
  num = 0;
  CL_SET_ARG(clState->CLbuffer0);
  CL_SET_ARG(clState->padbuffer8);
  // bmw - search1
  kernel = clState->extra_kernels;
  CL_SET_ARG_0(clState->padbuffer8);
  // groestl - search2
  CL_NEXTKERNEL_SET_ARG_0(clState->padbuffer8);
  // skein - search3
  CL_NEXTKERNEL_SET_ARG_0(clState->padbuffer8);
  // jh - search4
  CL_NEXTKERNEL_SET_ARG_0(clState->padbuffer8);
  // keccak - search5
  CL_NEXTKERNEL_SET_ARG_0(clState->padbuffer8);
  // luffa - search6
  CL_NEXTKERNEL_SET_ARG_0(clState->padbuffer8);
  // cubehash - search7
  CL_NEXTKERNEL_SET_ARG_0(clState->padbuffer8);
  // shavite - search8
  CL_NEXTKERNEL_SET_ARG_0(clState->padbuffer8);
  // simd - search9
  CL_NEXTKERNEL_SET_ARG_0(clState->padbuffer8);
  // echo - search10
  num = 0;
  CL_NEXTKERNEL_SET_ARG(clState->padbuffer8);
  CL_SET_ARG(clState->outputBuffer);
  CL_SET_ARG(le_target);

  return status;
}

static cl_int queue_marucoin_mod_kernel(struct __clState *clState, struct _dev_blk_ctx *blk, __maybe_unused cl_uint threads)
{
  cl_kernel *kernel;
  unsigned int num;
  cl_ulong le_target;
  cl_int status = 0;

  le_target = *(cl_ulong *)(blk->work->device_target + 24);
  flip80(clState->cldata, blk->work->data);
  status = clEnqueueWriteBuffer(clState->commandQueue, clState->CLbuffer0, true, 0, 80, clState->cldata, 0, NULL,NULL);

  // blake - search
  kernel = &clState->kernel;
  num = 0;
  CL_SET_ARG(clState->CLbuffer0);
  CL_SET_ARG(clState->padbuffer8);
  // bmw - search1
  kernel = clState->extra_kernels;
  CL_SET_ARG_0(clState->padbuffer8);
  // groestl - search2
  CL_NEXTKERNEL_SET_ARG_0(clState->padbuffer8);
  // skein - search3
  CL_NEXTKERNEL_SET_ARG_0(clState->padbuffer8);
  // jh - search4
  CL_NEXTKERNEL_SET_ARG_0(clState->padbuffer8);
  // keccak - search5
  CL_NEXTKERNEL_SET_ARG_0(clState->padbuffer8);
  // luffa - search6
  CL_NEXTKERNEL_SET_ARG_0(clState->padbuffer8);
  // cubehash - search7
  CL_NEXTKERNEL_SET_ARG_0(clState->padbuffer8);
  // shavite - search8
  CL_NEXTKERNEL_SET_ARG_0(clState->padbuffer8);
  // simd - search9
  CL_NEXTKERNEL_SET_ARG_0(clState->padbuffer8);
  // echo - search10
  CL_NEXTKERNEL_SET_ARG_0(clState->padbuffer8);
  // hamsi - search11
  CL_NEXTKERNEL_SET_ARG_0(clState->padbuffer8);
  // fugue - search12
  num = 0;
  CL_NEXTKERNEL_SET_ARG(clState->padbuffer8);
  CL_SET_ARG(clState->outputBuffer);
  CL_SET_ARG(le_target);

  return status;
}


static cl_int queue_marucoin_mod_old_kernel(struct __clState *clState, struct _dev_blk_ctx *blk, __maybe_unused cl_uint threads)
{
  cl_kernel *kernel;
  unsigned int num;
  cl_ulong le_target;
  cl_int status = 0;

  le_target = *(cl_ulong *)(blk->work->device_target + 24);
  flip80(clState->cldata, blk->work->data);
  status = clEnqueueWriteBuffer(clState->commandQueue, clState->CLbuffer0, true, 0, 80, clState->cldata, 0, NULL,NULL);

  // blake - search
  kernel = &clState->kernel;
  num = 0;
  CL_SET_ARG(clState->CLbuffer0);
  CL_SET_ARG(clState->padbuffer8);
  // bmw - search1
  kernel = clState->extra_kernels;
  CL_SET_ARG_0(clState->padbuffer8);
  // groestl - search2
  CL_NEXTKERNEL_SET_ARG_0(clState->padbuffer8);
  // skein - search3
  CL_NEXTKERNEL_SET_ARG_0(clState->padbuffer8);
  // jh - search4
  CL_NEXTKERNEL_SET_ARG_0(clState->padbuffer8);
  // keccak - search5
  CL_NEXTKERNEL_SET_ARG_0(clState->padbuffer8);
  // luffa - search6
  CL_NEXTKERNEL_SET_ARG_0(clState->padbuffer8);
  // cubehash - search7
  CL_NEXTKERNEL_SET_ARG_0(clState->padbuffer8);
  // shavite - search8
  CL_NEXTKERNEL_SET_ARG_0(clState->padbuffer8);
  // simd - search9
  CL_NEXTKERNEL_SET_ARG_0(clState->padbuffer8);
  // combined echo, hamsi, fugue - search10
  num = 0;
  CL_NEXTKERNEL_SET_ARG(clState->padbuffer8);
  CL_SET_ARG(clState->outputBuffer);
  CL_SET_ARG(le_target);

  return status;
}

typedef struct _algorithm_settings_t {
    const char *name; /* Human-readable identifier */
    char*    kernelname; /* Default kernel */
    uint8_t  nfactor;  /* Factor of N above (n = 2^nfactor) */
    double   diff_multiplier1;
    double   diff_multiplier2;
    double   share_diff_multiplier;
    uint32_t xintensity_shift;
    uint32_t intensity_shift;
    uint32_t found_idx;
    unsigned long long   diff_nonce;
    unsigned long long   diff_numerator;
    uint32_t diff1targ;
    size_t n_extra_kernels;
    long rw_buffer_size;
    cl_command_queue_properties cq_properties;
    void     (*regenhash)(struct work *);
    cl_int   (*queue_kernel)(struct __clState *, struct _dev_blk_ctx *, cl_uint);
    void     (*gen_hash)(const unsigned char *, unsigned int, unsigned char *);
} algorithm_settings_t;

static algorithm_settings_t algos[] = {
    // kernels starting from this will have difficulty calculated by using litecoin algorithm
#define A_SCRYPT(a, b, c, d) \
    { a, b, c, 1, 65536, 65536, 0, 0, 0xFF, 0x0000ffff00000000ULL, 0xFFFFFFFFULL, 0x0000ffffUL, 0, -1, CL_QUEUE_OUT_OF_ORDER_EXEC_MODE_ENABLE, d, queue_scrypt_kernel, gen_hash}
    A_SCRYPT( "scrypt", "ckolivas", 10, scrypt_regenhash ),
    A_SCRYPT( "nscrypt", "ckolivas", 11, scrypt_regenhash ),
    A_SCRYPT( "scrypt-jane", "scrypt-jane", 10, sj_scrypt_regenhash),
#undef A_SCRYPT

    // kernels starting from this will have difficulty calculated by using quarkcoin algorithm
#define A_QUARK(a, b) \
    { a, a, 0, 256, 256, 256, 0, 0, 0xFF, 0x000000ffff000000ULL, 0xFFFFFFULL, 0x0000ffffUL, 0, 0, CL_QUEUE_OUT_OF_ORDER_EXEC_MODE_ENABLE, b, queue_sph_kernel, gen_hash}
    A_QUARK( "quarkcoin", quarkcoin_regenhash),
    A_QUARK( "qubitcoin", qubitcoin_regenhash),
    A_QUARK( "animecoin", animecoin_regenhash),
    A_QUARK( "sifcoin",   sifcoin_regenhash),
#undef A_QUARK

    // kernels starting from this will have difficulty calculated by using bitcoin algorithm
#define A_DARK(a, b) \
    { a, a, 0, 1, 1, 1, 0, 0, 0xFF, 0x00000000ffff0000ULL, 0xFFFFULL, 0x0000ffffUL, 0, 0, CL_QUEUE_OUT_OF_ORDER_EXEC_MODE_ENABLE, b, queue_sph_kernel, gen_hash}
    A_DARK( "darkcoin",           darkcoin_regenhash),
    A_DARK( "inkcoin",            inkcoin_regenhash),
    A_DARK( "myriadcoin-groestl", myriadcoin_groestl_regenhash),
    A_DARK( "marucoin",           marucoin_regenhash),
#undef A_DARK

#define A_DARK_MOD(a, b, c, d, e, f, g, h) \
    { a, a, 0, 1, b, 1, c,  d, e, 0x00000000ffff0000ULL, 0xFFFFULL, f, 0, 0, CL_QUEUE_OUT_OF_ORDER_EXEC_MODE_ENABLE, g, h, sha256}
    A_DARK_MOD( "twecoin",   1, 0,  0, 0xFF, 0x0000ffffUL, twecoin_regenhash, queue_sph_kernel),
    A_DARK_MOD( "maxcoin", 256, 4, 15, 0x0F, 0x000000ffUL, maxcoin_regenhash, queue_maxcoin_kernel),
#undef A_DARK_MOD

#define A_DARK_MOD(a, b, c, d) \
    { a, a, 0, 1, 1, 1, 0, 0, 0xFF, 0x00000000ffff0000ULL, 0xFFFFULL, 0x0000ffffUL, b, 8 * 16 * 4194304, 0, c, d, gen_hash}
    A_DARK_MOD( "darkcoin-mod", 10, darkcoin_regenhash, queue_darkcoin_mod_kernel),
    A_DARK_MOD( "marucoin-mod", 12, marucoin_regenhash, queue_marucoin_mod_kernel),
    A_DARK_MOD( "marucoin-modold", 10, marucoin_regenhash, queue_marucoin_mod_old_kernel),
#undef A_DARK_MOD

    // kernels starting from this will have difficulty calculated by using fuguecoin algorithm
#define A_FUGUE(a, b) \
    { a, a, 0, 1, 256, 256, 0, 0, 0xFF, 0x00000000ffff0000ULL, 0xFFFFULL, 0x0000ffffUL, 0, 0, CL_QUEUE_OUT_OF_ORDER_EXEC_MODE_ENABLE, b, queue_sph_kernel, sha256}
    A_FUGUE( "fuguecoin",   fuguecoin_regenhash),
    A_FUGUE( "groestlcoin", groestlcoin_regenhash),
#undef A_FUGUE

    // Terminator (do not remove)
    { NULL, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, NULL, NULL, NULL}
};

void set_algorithm(algorithm_t* dest, const char* algo) {
    algorithm_settings_t* src;

    // Find algorithm settings and copy
    for (src = algos; src->name; src++) {
        if (strcmp(src->name, algo) == 0) {
            dest->name = src->name;
            dest->kernelname = src->kernelname;
            dest->nfactor = src->nfactor;
            dest->diff_multiplier1 = src->diff_multiplier1;
            dest->diff_multiplier2 = src->diff_multiplier2;
            dest->share_diff_multiplier = src->share_diff_multiplier;
            dest->xintensity_shift = src->xintensity_shift;
            dest->intensity_shift = src->intensity_shift;
            dest->found_idx = src->found_idx;
            dest->diff_nonce = src->diff_nonce;
            dest->diff_numerator = src->diff_numerator;
            dest->diff1targ = src->diff1targ;
            dest->n_extra_kernels = src->n_extra_kernels;
            dest->rw_buffer_size = src->rw_buffer_size;
            dest->cq_properties = src->cq_properties;
            dest->regenhash = src->regenhash;
            dest->queue_kernel = src->queue_kernel;
            dest->gen_hash = src->gen_hash;
            // Doesn't matter for non-scrypt algorithms
            set_algorithm_nfactor(dest, dest->nfactor);
            break;
        }
    }

    // if not found
    if (src->name == NULL) {
        applog(LOG_WARNING, "Algorithm %s not found, using %s.", algo, algos->name);
        set_algorithm(dest, algos->name);
    }
}

void set_algorithm_nfactor(algorithm_t* algo, const uint8_t nfactor) {
    algo->nfactor = nfactor;
    algo->n = (1 << nfactor);
}

bool cmp_algorithm(algorithm_t* algo1, algorithm_t* algo2) {
    return (strcmp(algo1->name, algo2->name) == 0) &&
          (algo1->nfactor == algo2->nfactor);
}
