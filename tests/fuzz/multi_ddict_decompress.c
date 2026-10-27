/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under both the BSD-style license (found in the
 * LICENSE file in the root directory of this source tree) and the GPLv2 (found
 * in the COPYING file in the root directory of this source tree).
 * You may select, at your option, one of the above-listed licenses.
 */

/**
 * This fuzz target references several DDicts on one DCtx, optionally with
 * ZSTD_d_refMultipleDDicts enabled, then decompresses the fuzzed data with the
 * one-shot or streaming API, resets the DCtx, re-references a subset of the
 * DDicts and decompresses again. The number of dictionaries, their dictIDs and
 * content types are chosen by the fuzzer.
 */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "fuzz_helpers.h"
#include "zstd_helpers.h"
#include "fuzz_data_producer.h"
#include "mem.h"

#define MAX_DDICTS 128

static void decompress(ZSTD_DCtx *dctx, const uint8_t *src, size_t size,
                       FUZZ_dataProducer_t *producer)
{
    size_t const bufSize = FUZZ_dataProducer_uint32Range(producer, 0, 10 * size);
    void *rBuf = FUZZ_malloc(bufSize);
    if (FUZZ_dataProducer_uint32Range(producer, 0, 1) == 0) {
        ZSTD_decompressDCtx(dctx, rBuf, bufSize, src, size);
    } else {
        ZSTD_inBuffer in = { src, size, 0 };
        while (in.pos < in.size) {
            ZSTD_outBuffer out = { rBuf, bufSize, 0 };
            size_t const prevPos = in.pos;
            size_t const ret = ZSTD_decompressStream(dctx, &out, &in);
            if (ZSTD_isError(ret) || (in.pos == prevPos && out.pos == 0))
                break;
        }
    }
    free(rBuf);
}

int LLVMFuzzerTestOneInput(const uint8_t *src, size_t size)
{
    /* Give a random portion of src data to the producer, to use for
    parameter generation. The rest will be used for decompression */
    FUZZ_dataProducer_t *producer = FUZZ_dataProducer_create(src, size);
    ZSTD_DDict *ddicts[MAX_DDICTS];
    unsigned nbDDicts;
    unsigned i;
    FUZZ_dict_t dict;
    ZSTD_DCtx *dctx;

    size = FUZZ_dataProducer_reserveDataPrefix(producer);
    dict = FUZZ_train(src, size, producer);
    nbDDicts = FUZZ_dataProducer_uint32Range(producer, 1, MAX_DDICTS);

    /* Build each DDict from a copy of the trained dictionary, with its own
     * dictID, so the DDicts can be told apart by the frame's dictID. */
    for (i = 0; i < nbDDicts; ++i) {
        void *buff = FUZZ_malloc(dict.size);
        if (dict.size)
            memcpy(buff, dict.buff, dict.size);
        if (dict.size >= 8 && MEM_readLE32(buff) == ZSTD_MAGIC_DICTIONARY)
            MEM_writeLE32((char *)buff + 4, FUZZ_dataProducer_uint32(producer));
        ddicts[i] = ZSTD_createDDict_advanced(buff, dict.size, ZSTD_dlm_byCopy,
                (ZSTD_dictContentType_e)FUZZ_dataProducer_uint32Range(producer, 0, 2),
                ZSTD_defaultCMem);
        free(buff);
    }

    dctx = ZSTD_createDCtx();
    FUZZ_ASSERT(dctx);
    FUZZ_ZASSERT(ZSTD_DCtx_setParameter(dctx, ZSTD_d_refMultipleDDicts,
            FUZZ_dataProducer_uint32Range(producer, 0, 1)));
    for (i = 0; i < nbDDicts; ++i) {
        if (ddicts[i])
            FUZZ_ZASSERT(ZSTD_DCtx_refDDict(dctx, ddicts[i]));
    }
    decompress(dctx, src, size, producer);

    /* Reset, then re-reference a subset of the DDicts and decompress again. */
    {
        ZSTD_ResetDirective reset = (ZSTD_ResetDirective)
            FUZZ_dataProducer_uint32Range(producer, 1, 3);
        if (ZSTD_isError(ZSTD_DCtx_reset(dctx, reset))) {
            /* Resetting only the parameters is refused mid-frame. */
            FUZZ_ASSERT(reset == ZSTD_reset_parameters);
            reset = ZSTD_reset_session_and_parameters;
            FUZZ_ZASSERT(ZSTD_DCtx_reset(dctx, reset));
        }
        if (reset != ZSTD_reset_session_only)
            FUZZ_ZASSERT(ZSTD_DCtx_setParameter(dctx, ZSTD_d_refMultipleDDicts,
                    FUZZ_dataProducer_uint32Range(producer, 0, 1)));
        for (i = 0; i < nbDDicts; ++i) {
            if (ddicts[i] && FUZZ_dataProducer_uint32Range(producer, 0, 1))
                FUZZ_ZASSERT(ZSTD_DCtx_refDDict(dctx, ddicts[i]));
        }
        decompress(dctx, src, size, producer);
    }

    /* The DCtx may still reference the DDicts, so free it first. */
    ZSTD_freeDCtx(dctx);
    for (i = 0; i < nbDDicts; ++i)
        ZSTD_freeDDict(ddicts[i]);
    free(dict.buff);
    FUZZ_dataProducer_free(producer);
    return 0;
}
