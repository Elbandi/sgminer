#ifndef FINDNONCE_H
#define FINDNONCE_H

#include "miner.h"

#define MAXTHREADS (0xFFFFFFFEULL)
#define MAXBUFFERS (0x100)
#define BUFFERSIZE (sizeof(uint32_t) * MAXBUFFERS)

#define THASHBUFSIZE (8 * 16 * 4194304)

extern void precalc_hash(dev_blk_ctx *blk, uint32_t *state, uint32_t *data);
extern void postcalc_hash_async(struct thr_info *thr, struct work *work, uint32_t *res);

#endif /*FINDNONCE_H*/
