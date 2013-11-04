#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include "safe-math.h"

struct pdb_header {
    char magic[32];
    uint32_t page_size;
    uint32_t alloc_table_ptr;
    uint32_t num_file_pages;
    uint32_t root_size;
    uint32_t reserved;
    uint32_t root_index_index[0x49];
};

struct off_cb {
    int32_t off, cb;
};

struct tpi_hash {
    uint16_t sn, pad;
    uint32_t hash_key, buckets;
    struct off_cb hash_vals, ti_off, hash_adj;
};

struct tpi_header {
    uint32_t version;
    int32_t hdr_size;
    uint32_t ti_min, ti_max;
    uint32_t follow_size;
    struct tpi_hash hash;
};

struct lf_structure {
    uint16_t count, flags;
    uint32_t fieldlist, derived, vshape;
};

static size_t pdb_size;
static void *pdb_map;
static uint32_t page_size;

static struct paged *streams;
static uint32_t num_streams;

static struct tpi_type {
    uint32_t offset, size;
} *tpi_types;
static uint32_t tpi_ntypes;
struct tpi_header tpi_hdr;

static inline uint32_t pages(uint32_t size) {
    return (((uint64_t) size) + page_size - 1) / page_size;
}

struct paged {
    uint32_t *indices;
    uint32_t npages;
    uint32_t size;
    void *cur_ptr;
    uint32_t pos;
    void *temp;
    uint32_t temp_size;
};

static inline void paged_seek(struct paged *paged, uint32_t pos) {
    if(paged->pos == pos) {
        return;
    }
    assert(pos <= paged->size);
    paged->pos = pos;
    uint32_t index = paged->indices[pos / page_size];
    assert(index < pdb_size / page_size);
    paged->cur_ptr = (char *) pdb_map + page_size * index;
}

static void paged_init(struct paged *paged, uint32_t *indices, uint32_t size) {
    assert(size <= UINT32_MAX - page_size);
    uint32_t npages = pages(size);
    assert((char *) pdb_map + pdb_size - (char *) indices >= npages * sizeof(uint32_t));
    paged->indices = indices;
    paged->size = size;
    paged->npages = npages;
    paged->pos = -1;
    paged->temp = NULL;
    paged->temp_size = 0;
    paged_seek(paged, 0);
}

static inline void paged_free(void *ptr) {
    if((uintptr_t) ptr - (uintptr_t) pdb_map >= pdb_size) {
        free(ptr);
    }
}

static inline void *paged_use(struct paged *paged, void *ptr) {
    if(ptr == paged->temp) {
        paged->temp = NULL;
        paged->temp_size = 0;
    }
    return ptr;
}

static void *paged_read(struct paged *paged, void *ptr, size_t size) {
    while(size) {
        uint32_t page_off = paged->pos % page_size;
        uint32_t this_size = MIN(size, page_size - page_off);
        memcpy(ptr, (char *) paged->cur_ptr + page_off, this_size);
        paged_seek(paged, paged->pos + this_size);
        ptr = (char *) ptr + this_size;
        size -= this_size;
    }
    return paged->temp;
}

static void *paged_get(struct paged *paged, size_t size) {
    assert(size <= paged->size - paged->pos);
    uint32_t page_off = paged->pos % page_size;
    if(size < page_size - page_off) {
        paged->pos += size;
        return (char *) paged->cur_ptr + page_off;
    } else {
        if(paged->temp_size < size) {
            free(paged->temp);
            paged->temp = malloc(size);
            paged->temp_size = size;
        }
        paged_read(paged, paged->temp, size);
        return paged->temp;
    }
}

static inline struct paged paged_clone(struct paged *paged) {
    struct paged ret = *paged;
    ret.temp = NULL;
    ret.temp_size = 0;
    return ret;
}

#define PGET(paged, type) (*(type *) paged_get((paged), sizeof(type)))

static void parse_root() {
    struct pdb_header *ph = pdb_map;
    assert(pdb_size >= sizeof(*ph));
    assert(!memcmp(ph->magic, "Microsoft C/C++ MSF 7.00\r\n\x1a\x44S\0\0\0", sizeof(ph->magic)));
    page_size = ph->page_size;
    uint32_t root_npages = pages(ph->root_size);
    uint32_t root_index_size = smul(root_npages,  sizeof(uint32_t));
    uint32_t root_index_npages = pages(root_index_size);
    assert(root_index_npages <= 0x49);
    struct paged ri_p, root_p;
    paged_init(&ri_p, ph->root_index_index, root_index_size);
    uint32_t *root_index = paged_use(&ri_p, paged_get(&ri_p, root_index_size));
    paged_init(&root_p, root_index, ph->root_size);
    paged_read(&root_p, &num_streams, sizeof(num_streams));
    streams = malloc(smul(num_streams, sizeof(*streams)));
    for(uint32_t i = 0; i < num_streams; i++) {
        uint32_t *p = paged_get(&root_p, sizeof(uint32_t));
        streams[i].size = *p;
    }
    for(uint32_t i = 0; i < num_streams; i++) {
        uint32_t npages = pages(streams[i].size);
        uint32_t *index = paged_use(&root_p, paged_get(&root_p, smul(npages, sizeof(uint32_t))));
        paged_init(&streams[i], index, streams[i].size);
    }
}

static void get_cstring(struct paged *p, const char **str) {
    uint32_t len = 32;
    uint32_t pos = p->pos;
    while(1) {
        bool is_long = len >= p->size - pos;
        if(is_long) len = p->size - pos;
        *str = paged_get(p, len);
        uint32_t slen = strnlen(*str, len);
        if(slen < len) {
            paged_seek(p, pos + slen + 1);
            return;
        }
        assert(!is_long);
        len *= 2;
        paged_seek(p, pos);
    }
}

static void get_val(struct paged *p, long long *val) {
    uint16_t val_kind = PGET(p, uint16_t);
    switch(val_kind) {
    #define X(kind, type) case kind: *val = PGET(p, type); break;
        X(0x8000, char) // LF_CHAR
        X(0x8001, int16_t) // LF_SHORT
        X(0x8002, uint16_t) // LF_USHORT
        X(0x8003, int32_t) // LF_LONG
        X(0x8004, uint32_t) // LF_ULONG
    #undef X
        case 0 ... 0x7fff: *val = val_kind; break;
        default:
            printf("unknown kind %x\n", (int) val_kind);
            assert(false);
    }
}

static const char *get_pascal(struct paged *p) {
    uint8_t size = PGET(p, uint8_t);
    return paged_get(p, size);
}

static void tpi_info(uint32_t ti, const char **name, int64_t *struct_ti) {
    static char buf[4096];
    if(struct_ti) *struct_ti = -1;
    if(name) *name = buf;
    if(!(ti >= tpi_hdr.ti_min && ti < tpi_hdr.ti_max)) {
        snprintf(buf, sizeof(buf), "[0x%x]", ti);
        return;
    }
    struct paged *p = &streams[2];
    uint32_t pos = p->pos;
    paged_seek(p, tpi_types[ti - tpi_hdr.ti_min].offset);
    uint16_t leaf_type = PGET(p, uint16_t);
    if(leaf_type == 0x1002) { // LF_POINTER
        struct lf_pointer {
            uint32_t type;
            uint32_t flags;
        } lfp = PGET(p, struct lf_pointer);
        tpi_info(lfp.type, NULL, NULL);
        strlcat(buf, "*", sizeof(buf));
    } else if(leaf_type == 0x1001) { // LF_MODIFIER
        struct lf_modifier {
            uint32_t type;
            uint16_t flags;
        } lfm = PGET(p, struct lf_modifier);
        tpi_info(lfm.type, NULL, struct_ti);
    } else if(leaf_type == 0x1505 || leaf_type == 0x1504) { // LF_STRUCTURE/CLASS
        if(struct_ti) *struct_ti = ti;
        PGET(p, struct lf_structure);
        int64_t size;
        get_val(p, &size);
        const char *name;
        get_cstring(p, &name);
        strlcpy(buf, name, sizeof(buf));
    } else {
        snprintf(buf, sizeof(buf), "[type 0x%x]", leaf_type);
    }
    paged_seek(p, pos);
}

static inline const char *tpi_type_name(uint32_t ti) {
    const char *ret;
    tpi_info(ti, &ret, NULL);
    return ret;
}

static uint32_t tpi_hash(const char *name) {
    uint32_t hash = 0;
    size_t len = strlen(name);
    size_t i;
    for(i = 4; i <= len; i += 4) {
        hash ^= name[i-4] | (name[i-3] << 8) | (name[i-2] << 16) | (name[i-1] << 24);
    }
    if(len & 2) {
        hash ^= name[i-4] | (name[i-3] << 8);
        i += 2;
    }
    if(len & 1) {
        hash ^= name[i-4];
    }
    hash |= 0x20202020;
    hash ^= hash >> 11;
    hash ^= hash >> 16;
    return hash % tpi_hdr.hash.buckets;
}

static int64_t tpi_get_ti(const char *name) {
    uint32_t bucket = tpi_hash(name);
    struct paged sp = paged_clone(&streams[tpi_hdr.hash.sn]);
    struct paged *p = &streams[2];
    paged_seek(&sp, tpi_hdr.hash.hash_vals.off);
    // wat
    for(uint32_t ti = tpi_hdr.ti_min; ti < tpi_hdr.ti_max; ti++) {
        if(PGET(&sp, uint32_t) == bucket && !strcmp(tpi_type_name(ti), name)) {
            return ti;
        }
    }
    return -1;
}

static void print_tpi(uint32_t ti, bool print_bases, uint32_t outer_offset);

static void print_base(uint32_t ti, uint32_t offset) {
    struct paged *p = &streams[2];
    uint32_t pos = p->pos;
    const char *name;
    int64_t bti;
    tpi_info(ti, &name, &bti);
    if(bti == -1) {
        printf("%s\n", name);
    } else {
        char *namep = strdup(name);
        int64_t ti = tpi_get_ti(namep);
        free(namep);
        assert(ti != -1);
        print_tpi(ti, true, offset);
    }
    paged_seek(p, pos);
}

static void print_tpi(uint32_t ti, bool print_bases, uint32_t outer_offset) {
    struct paged *p = &streams[2];
    assert(ti >= tpi_hdr.ti_min && ti < tpi_hdr.ti_max);
    paged_seek(p, tpi_types[ti - tpi_hdr.ti_min].offset);
    uint16_t leaf_type = PGET(p, uint16_t);
    if(leaf_type == 0x1505 || leaf_type == 0x1504) { // LF_STRUCTURE/CLASS
        struct lf_structure lfs = PGET(p, struct lf_structure);
        if(lfs.flags & 0x80) { // forward reference
            return;
        }
        const char *name;
        int64_t size;
        get_val(p, &size);
        get_cstring(p, &name);
        printf("%s [0x%llx]\n", name, size);
        if(!lfs.fieldlist) {
            printf("   no field list\n");
            return;
        }
        uint32_t fl = lfs.fieldlist - tpi_hdr.ti_min;
        assert(fl < tpi_ntypes);
        paged_seek(p, tpi_types[fl].offset);
        uint16_t leaf_type_2 = PGET(p, uint16_t);
        assert(leaf_type_2 == 0x1203); // LF_FIELDLIST
        while(p->pos - tpi_types[fl].offset < tpi_types[fl].size) {
            uint16_t leaf_type_3 = PGET(p, uint16_t);
            struct lf_attr_index {
                uint16_t attr;
                uint32_t index;
            } __attribute__((packed));
            switch(leaf_type_3) {
            case 0x1405: { // LF_MEMBER_ST
                struct lf_member_st {
                    uint16_t attr;
                    uint32_t index;
                    uint16_t offset;
                } __attribute__((packed)) lfm = PGET(p, struct lf_member_st);
                printf("   +0x%x: [st] %s : ", lfm.offset + outer_offset, get_pascal(p));
                printf("%s\n", tpi_type_name(lfm.index));
                break;
            }
            case 0x150d: { // LF_MEMBER
                struct lf_attr_index lfm = PGET(p, struct lf_attr_index);
                const char *member_name;
                long long offset;
                get_val(p, &offset);
                get_cstring(p, &member_name);
                printf("   +0x%llx: %s : ", offset + outer_offset, member_name);
                if(print_bases) {
                    print_base(lfm.index, offset + outer_offset);
                } else {
                    printf("%s\n", tpi_type_name(lfm.index));
                }
                break;
            }
            case 0x150e: { // LF_STMEMBER
                struct lf_attr_index lfm = PGET(p, struct lf_attr_index);
                const char *member_name;
                get_cstring(p, &member_name);
                printf("   static %s\n", member_name);
                break;
            }
            case 0x1400: { // LF_BCLASS
                struct lf_attr_index lfb = PGET(p, struct lf_attr_index);
                long long offset;
                get_val(p, &offset);
                if(print_bases) {
                    printf("   +0x%llx: base: ", offset + outer_offset);
                    print_base(lfb.index, offset + outer_offset);
                } else {
                    printf("   +0x%llx: base %s\n", offset, tpi_type_name(lfb.index));
                }
                break;
            }
            case 0x1402: // LF_IVBCLASS
            case 0x1401: { // LF_VBCLASS
                struct lf_bclass {
                    uint16_t attr;
                    uint32_t unk1;
                    uint32_t unk2;
                } __attribute__((packed)) lfb = PGET(p, struct lf_bclass);
                long long offset, unk4;
                get_val(p, &offset);
                get_val(p, &unk4);
                printf("   +0x%llx: %svirtual base %s\n", offset + outer_offset, leaf_type_3 == 0x1402 ? "(i) " : "", tpi_type_name(lfb.unk1));
                break;
            }
            case 0x1409: { // LF_VFUNCTAB
                struct lf_attr_index lfv = PGET(p, struct lf_attr_index);
                printf("   vfunctab (%x %s)\n", lfv.index, tpi_type_name(lfv.index));
                break;
            }
            case 0x1511: { // LF_ONEMETHOD
                struct lf_attr_index lfo = PGET(p, struct lf_attr_index);
                int intro = (lfo.attr >> 2) & 7;
                bool has_vtoff = intro == 4 || intro == 6; // CV_MT{intro,pureintro}
                uint32_t vtoff;
                if(has_vtoff) {
                    vtoff = PGET(p, uint32_t);
                }
                const char *method_name;
                get_cstring(p, &method_name);
                if(has_vtoff) {
                    printf("   vt+0x%x: %s\n", vtoff, method_name);
                }
                break;
            }
            case 0x150f: { // LF_METHOD
                struct lf_method {
                    uint16_t count;
                    uint32_t mlist;
                } __attribute__((packed)) lfm = PGET(p, struct lf_method);
                const char *name;
                get_cstring(p, &name);
                paged_use(p, (void *) name);
                uint32_t pos = p->pos;
                assert(lfm.mlist >= tpi_hdr.ti_min && lfm.mlist < tpi_hdr.ti_max);
                struct tpi_type tt = tpi_types[lfm.mlist - tpi_hdr.ti_min];
                paged_seek(p, tt.offset);
                assert(PGET(p, uint16_t) == 0x1206); // LF_METHODLIST
                while(p->pos < tt.offset + tt.size) {
                    struct lf_methodlist_entry {
                        uint16_t attr;
                        uint16_t pad;
                        uint32_t index;
                    } __attribute__((packed)) lfe = PGET(p, struct lf_methodlist_entry);
                    int intro = (lfe.attr >> 2) & 7;
                    if(intro == 4 || intro == 6) {
                        uint32_t vtoff = PGET(p, uint32_t);
                        printf("   vt+0x%x: %s [o]\n", vtoff, name);
                    }
                }
                paged_seek(p, pos);
                paged_free((void *) name);
                break;
            }
            case 0x1510: { // LF_NESTTYPE
                struct lf_attr_index lfn = PGET(p, struct lf_attr_index);
                const char *name;
                get_cstring(p, &name);
                //printf("   nested typedef %s\n", name);
                break;
            }
            default:
                printf("   unknown leaf type %x\n", (int) leaf_type_3);
                assert(false);
            }
            uint32_t pos = p->pos;
            uint8_t pad = PGET(p, uint8_t);
            if(pad > 0xf0) {
                paged_get(p, (pad & 0x0f) - 1);
            } else {
                paged_seek(p, pos);
            }
        }
    }
}

static void parse_tpi() {
    assert(num_streams > 2);
    struct paged *p = &streams[2];
    paged_read(p, &tpi_hdr, sizeof(tpi_hdr));
    assert(tpi_hdr.hdr_size == sizeof(tpi_hdr));
    assert(tpi_hdr.hash.sn < num_streams);
    tpi_ntypes = tpi_hdr.ti_max - tpi_hdr.ti_min;
    struct tpi_type *tp = tpi_types = malloc(smul(tpi_ntypes, sizeof(*tpi_types)));
    for(uint32_t i = 0; i < tpi_ntypes; i++) {
        tp->size = PGET(p, uint16_t);
        tp->offset = p->pos;
        paged_get(p, tp->size);
        tp++;
    }
}


int main(int argc, char **argv) {
    int fd = open(argv[1], O_RDONLY);
    assert(fd != -1);
    off_t size = lseek(fd, 0, SEEK_END);
    pdb_size = size;
    assert(pdb_size == size);
    pdb_map = mmap(NULL, pdb_size, PROT_READ, MAP_SHARED, fd, 0);
    assert(pdb_map != MAP_FAILED);
    parse_root();
    parse_tpi();
    const char *match = argv[2];
    bool print_bases = match;
    if(match) {
        int64_t ti = tpi_get_ti(match);
        if(ti != -1) {
            print_tpi(ti, true, 0);
        }
    } else {
        for(uint32_t i = 0; i < tpi_ntypes; i++) {
            if(!print_bases && i % 1000 == 0) {
                fprintf(stderr, "%u/%u\n", i, tpi_ntypes);
            }
            print_tpi(i + tpi_hdr.ti_min, false, 0);
        }
    }
}
