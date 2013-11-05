#pragma once

static inline uint64_t sadd64(uint64_t a, uint64_t b) {
    uint64_t ret = a + b;
    assert(ret >= a);
    return ret;
}

static inline uint64_t ssub64(uint64_t a, uint64_t b) {
    uint64_t ret = a - b;
    assert(a >= b);
    return ret;
}

static inline uint64_t smul64(uint64_t a, uint64_t b) {
    uint64_t ret = a * b;
    assert(ret / b == a);
    return ret;
}

static inline uint64_t sadd32(uint64_t a, uint64_t b) {
    uint64_t ret = a + b;
    assert(ret >= a);
    return ret;
}

static inline uint32_t ssub32(uint32_t a, uint32_t b) {
    uint32_t ret = a - b;
    assert(a >= b);
    return ret;
}

static inline uint32_t smul32(uint32_t a, uint32_t b) {
    uint64_t ret64 = (uint64_t) a * b;
    uint32_t ret32 = ret64;
    assert(ret64 == ret32);
    return ret32;
}

static inline uint32_t sdown32(uint64_t a) {
    uint32_t ret = a;
    assert(ret == a);
    return ret;
}
