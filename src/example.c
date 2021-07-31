/* example.c - Last modified: 31-Jul-2021 (kobayasy)
 *
 * Copyright (c) 2021 by Yuichi Kobayashi <kobayasy@kobayasy.com>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "camellia.h"

int main(int argc, char *argv[]) {
    const uint8_t k128[16] = {  /* 128bitサイズキー */
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    const uint8_t k192[24] = {  /* 192bitサイズキー */
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
    };
    const uint8_t k256[32] = {  /* 256bitサイズキー */
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    const uint8_t p[16] = {  /* 動作確認用平文(128bit固定) */
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    const uint8_t c128[16] = {  /* 動作確認用暗号文期待値(128bit固定) */
        0x67, 0x67, 0x31, 0x38, 0x54, 0x96, 0x69, 0x73,
        0x08, 0x57, 0x06, 0x56, 0x48, 0xea, 0xbe, 0x43
    };
    const uint8_t c192[16] = {  /* 動作確認用暗号文期待値(128bit固定) */
        0xb4, 0x99, 0x34, 0x01, 0xb3, 0xe9, 0x96, 0xf8,
        0x4e, 0xe5, 0xce, 0xe7, 0xd7, 0x9b, 0x09, 0xb9
    };
    const uint8_t c256[16] = {  /* 動作確認用暗号文期待値(128bit固定) */
        0x9a, 0xcc, 0x23, 0x7d, 0xff, 0x16, 0xd7, 0x6c,
        0x20, 0xef, 0x7c, 0x91, 0x9e, 0x3a, 0x75, 0x09
    };
    CamelliaData data;  /* 変換テーブル */
    uint8_t v[16];
    int status = -1;

    /* Encrypt */
    if (camelliaKeysche(Camellia128Encrypt, k128, &data) < 0) goto error;
    memset(v, 0, sizeof(v));
    if (camelliaDatarand(p, &data, v) < 0) goto error;
    if (memcmp(v, c128, sizeof(v))) goto error;

    /* Decrypt */
    if (camelliaKeyswap(&data) < 0) goto error;
    memset(v, 0, sizeof(v));
    if (camelliaDatarand(c128, &data, v) < 0) goto error;
    if (memcmp(v, p, sizeof(v))) goto error;

    /* Encrypt */
    if (camelliaKeysche(Camellia192Encrypt, k192, &data) < 0) goto error;
    memset(v, 0, sizeof(v));
    if (camelliaDatarand(p, &data, v) < 0) goto error;
    if (memcmp(v, c192, sizeof(v))) goto error;

    /* Decrypt */
    if (camelliaKeyswap(&data) < 0) goto error;
    memset(v, 0, sizeof(v));
    if (camelliaDatarand(c192, &data, v) < 0) goto error;
    if (memcmp(v, p, sizeof(v))) goto error;

    /* Encrypt */
    if (camelliaKeysche(Camellia256Encrypt, k256, &data) < 0) goto error;
    memset(v, 0, sizeof(v));
    if (camelliaDatarand(p, &data, v) < 0) goto error;
    if (memcmp(v, c256, sizeof(v))) goto error;

    /* Decrypt */
    if (camelliaKeyswap(&data) < 0) goto error;
    memset(v, 0, sizeof(v));
    if (camelliaDatarand(c256, &data, v) < 0) goto error;
    if (memcmp(v, p, sizeof(v))) goto error;

    status = 0;
error:
    printf("%s\n", status < 0 ? "NG" : "OK");
    return status < 0 ? 1 : 0;
}
