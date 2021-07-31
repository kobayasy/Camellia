/* camellia.h - Last modified: 31-Jul-2021 (kobayasy)
 * The Camellia Encryption Algorithm (RFC 3713).
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

#ifndef _INCLUDE_camellia_h
#define _INCLUDE_camellia_h

#include <stdint.h>

/* 変換テーブル
 */
typedef enum {  /* 暗号/復号キー種別 */
    CamelliaUnknown=0,   /* 不明 */
    Camellia128Encrypt,  /* Camellia 128bit 暗号キー */
    Camellia128Decrypt,  /* Camellia 128bit 復号キー */
    Camellia192Encrypt,  /* Camellia 192bit 暗号キー */
    Camellia192Decrypt,  /* Camellia 192bit 復号キー */
    Camellia256Encrypt,  /* Camellia 256bit 暗号キー */
    Camellia256Decrypt   /* Camellia 256bit 復号キー */
} CamelliaKeytype;
typedef struct {  /* 暗号/復号 変換テーブル */
    CamelliaKeytype type;                                                 /* 暗号/復号キー種別 */
    uint64_t kw1, kw2, kw3, kw4;                                          /* RFC 3713 規定のサブキー変数 */
    uint64_t k1,  k2,  k3,  k4,  k5,  k6,  k7,  k8,  k9,  k10, k11, k12,  /* RFC 3713 規定のサブキー変数 */
             k13, k14, k15, k16, k17, k18, k19, k20, k21, k22, k23, k24;
    uint64_t ke1, ke2, ke3, ke4, ke5, ke6;                                /* RFC 3713 規定のサブキー変数 */
} CamelliaData;

/* RFC 3713 規定のキースケジューリング処理
 * type: 暗号/復号キー種別
 *  (Camellia128Encrypt, Camellia192Encrypt or Camellia256Encrypt)
 * k[n]: RFC 3713 規定の変数K
 *  (type=Camellia128Encrypt の場合 n=16, Camellia192Encrypt の場合 n=24, Camellia256Encrypt の場合 n=32)
 * data: 変換テーブル
 * 戻り値: 0以上=正常終了, 0未満=異常終了(未サポートな type を指定した)
 */
extern int camelliaKeysche(CamelliaKeytype type, const uint8_t *k,
                           CamelliaData *data );

/* 変換テーブルを暗号キーと復号キーに相互変換
 * data: 変換テーブル
 * 戻り値: 0以上=正常終了, 0未満=異常終了(未サポートな type を指定した)
 */
extern int camelliaKeyswap(CamelliaData *data);

/* RFC 3713 規定のデータランダム化処理
 * m[16]: RFC 3713 規定の変数M
 * data: 変換テーブル
 * c[16]: RFC 3713 規定の変数C
 * 戻り値: 0以上=正常終了, 0未満=異常終了(未サポートな type を指定した)
 */
extern int camelliaDatarand(const uint8_t *m, const CamelliaData *data,
                            uint8_t *c );

#endif  /* #ifndef _INCLUDE_camellia_h */
