#include "common.h"

void set_block_buffered(FILE *fp) {
    size_t size = 100000;
    char *buf = malloc(size);
    setbuffer(stdout, buf, size);
}

uint64_t read_leb128_rest(struct reader *r, bool is_signed) {
    uint64_t result = 0;
    int shift;
    uint8_t c = 0x80;
    for(shift = 0; c & 0x80; shift += 7) {
        c = read_t(uint8_t, r);
        result |= (c & 0x7f) << shift;
    }
    if(is_signed && shift > 0 && (result & (1 << (shift - 1))))
        result |= -(1 << shift);
    return result;
}

void tjson_newline(struct tjson *tj) {
    _putc('\n', tj->fp);
    size_t nspaces = tj->indent * 2;
    for (size_t i = 0; i < nspaces; i++)
        _putc(' ', tj->fp);
}

void tjson_str(struct tjson *tj, const char *str) {
    _tjson_item(tj);
    _putc('"', tj->fp);
    // this ignores control characters, in case anyone cares
    unsigned char c;
    while((c = *str++)) {
        if (c == '"' || c == '\\')
            _putc('\\', tj->fp);
        _putc(c, tj->fp);
    }
    _putc('"', tj->fp);
}
