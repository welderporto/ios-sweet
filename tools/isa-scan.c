/* Accelerated counterpart of check-isa.py classify(); reports candidates only. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
static int classify(uint32_t w) {
    if ((w & 0x3ffffc00u) == 0x38bfc000u) return 1;
    if ((w & 0x3f200c00u) == 0x38200000u) return 0;
    if ((w & 0x3fa07c00u) == 0x08a07c00u) return 0;
    if ((w & 0xbfa07c00u) == 0x08207c00u) return 0;
    if ((w & 0xfffff0ffu) == 0xd500409fu) return 2;
    if ((w & 0xffdfffe0u) == 0xd5184260u) return 2;
    if ((w & 0xfe9ff800u) == 0xd61f0800u) return 3;
    if ((w & 0xff200400u) == 0xf8200400u) return 3;
    if ((w & 0xffffc000u) == 0xdac10000u) return 3;
    if ((w & 0xffe0fc00u) == 0x9ac03000u) return 3;
    unsigned size = (w >> 22) & 3;
    if ((w & 0xbf20f400u) == 0x2e008400u && (size == 1 || size == 2)) return 4;
    if ((w & 0x9fe0fc00u) == 0x0e809400u) return 5;
    if ((w & 0x9f60c400u) == 0x0e400400u) return 6;
    return -1;
}
void isa_scan(const unsigned char *data, size_t length, uint64_t *counts,
              uint64_t *offsets, uint32_t *words) {
    for (size_t p = 0; p + 4 <= length; p += 4) {
        uint32_t w;
        memcpy(&w, data + p, 4);
        int c = classify(w);
        if (c < 0) continue;
        uint64_t n = counts[c]++;
        if (n < 3) { offsets[c * 3 + n] = p; words[c * 3 + n] = w; }
    }
}
