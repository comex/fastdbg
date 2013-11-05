#pragma once

/*
{typename: {
    'vtable': {offset: name...},
    'members': [{
        'offset', 'size', 'type', 'name'
    }...]
}...}
*/

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define UNUSED __attribute__((unused))

// https://github.com/attractivechaos/klib/issues/16 - seriously?
// also zeroes
#include "klib/kvec.h"
struct kvec_generic {
    size_t n, m;
    void *a;
};
static inline void kv_ensure_size(struct kvec_generic *kv, size_t esize, size_t i) {
    if(i >= kv->m) {
        size_t oldm = kv->m;
        kv->n = kv->m = i + 1;
        kv_roundup32(kv->m);
        kv->a = realloc(kv->a, esize * kv->m);
        memset(kv->a + esize * oldm, 0, esize * (kv->m - oldm));
    } else if(i >= kv->n) {
        kv->n = i + 1;
    }
}
#define kv_ap(type, v, i) (kv_ensure_size((struct kvec_generic *) &(v), sizeof(type), i), &kv_A(v, i))

#define panic(msg...) do { fprintf(stderr, msg); abort(); } while(0)

struct reader {
    void *ptr;
    void *end;
};

#define read_uleb128(r) read_leb128(r, false)
#define read_sleb128(r) ((int64_t) read_leb128(r, true))
static inline void *read_bytes(struct reader *r, size_t size) {
    assert(r->end - r->ptr >= size);
    void *ret = r->ptr;
    r->ptr += size;
    return ret;
}
#define read_t(type, r) (*(type *) read_bytes(r, sizeof(type)))

uint64_t read_leb128_rest(struct reader *r, bool is_signed);
static inline uint64_t read_leb128(struct reader *r, bool is_signed) {
    assert(r->ptr != r->end);
    uint8_t c = *(uint8_t *) r->ptr;
    if(c < 0x80) {
        r->ptr++;
        return c | ((is_signed && (c & 0x40)) ? ~(uint64_t)0x7f : 0);
    }
    return read_leb128_rest(r, is_signed);
}

static inline struct reader reader_slice(struct reader r, uint64_t offset, uint64_t size) {
    size_t rsize = r.end - r.ptr;
    assert(offset <= rsize && size <= rsize - offset);
    return (struct reader) {r.ptr + offset, r.ptr + offset + size};
}

static inline struct reader reader_slice_to_end(struct reader r, uint64_t offset) {
    size_t rsize = r.end - r.ptr;
    assert(offset <= rsize);
    return (struct reader) {r.ptr + offset, r.end};
}


// trivial JSON output

struct tjson {
    FILE *fp;
    size_t indent;
    bool haditem;
};

#define _putc putc_unlocked

void tjson_newline(struct tjson *tj);
void tjson_str(struct tjson *tj, const char *str);
static inline void tjson_list_start(struct tjson *tj) {
    _putc('[', tj->fp);
    tj->indent++;
    tj->haditem = false;
}
static inline void tjson_list_item(struct tjson *tj) {
    if (tj->haditem)
        _putc(',', tj->fp);
    tjson_newline(tj);
    tj->haditem = true;
}
static inline void _tjson_x_end(struct tjson *tj) {
    tj->indent--;
    if (tj->haditem)
        tjson_newline(tj);
    tj->haditem = true;
}
static inline void tjson_list_end(struct tjson *tj) {
    _tjson_x_end(tj);
    _putc(']', tj->fp);
}
static inline void tjson_dict_start(struct tjson *tj) {
    _putc('{', tj->fp);
    tj->indent++;
    tj->haditem = false;
}
static inline void tjson_dict_key(struct tjson *tj, const char *name) {
    tjson_list_item(tj);
    tjson_str(tj, name);
    fputs(": ", tj->fp);
}
static inline void tjson_dict_end(struct tjson *tj) {
    _tjson_x_end(tj);
    _putc('}', tj->fp);
}
