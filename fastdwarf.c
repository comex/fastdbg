#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include "safe-math.h"
#include "elf.h"
#include "dwarf2.h"
#include "common.h"
#include "klib/kvec.h"
#include "klib/khash.h"

struct dwarf_node {
    uint64_t tag;
    const char *at_name;
    uint64_t at_type;
    uint64_t at_byte_size;
    struct reader at_data_member_location;
};

struct dwarf_cached_attr {
    uint8_t name; // just for reference
    uint8_t form;
    uint8_t node_offset;
};

struct dwarf_abbr {
    uint64_t tag;
    bool has_children;
    struct dwarf_cached_attr *attrs;
};

struct dwarf_abbr_cu {
    kvec_t(struct dwarf_abbr) abbrs;
};

struct cu_ctx {
    struct reader full_r; // the entire CU
    struct reader r; // where we're reading now
    bool is64;
    // debug_info
    struct dwarf_abbr_cu *acu;

};

KHASH_MAP_INIT_INT64(abbr_cu, struct dwarf_abbr_cu)
static khash_t(abbr_cu) dwarf_abbr_cus;
static struct reader debug_str, debug_info;

static struct reader read_cstr(struct reader *r) {
    size_t len = strnlen(r->ptr, r->end - r->ptr);
    if(len == r->end - r->ptr)
        panic("read_cstr: no null terminator");
    void *ptr = r->ptr;
    r->ptr += len + 1;
    return (struct reader) {ptr, ptr + len};
}

static uint64_t read_addr(struct cu_ctx *cu) {
    return cu->is64 ? read_t(uint64_t, &cu->r) : read_t(uint32_t, &cu->r);
}

// return whether there was a node (as opposed to a child end marker)
static bool parse_die(struct cu_ctx *cu, struct dwarf_node *node) {
    struct reader *r = &cu->r;
    uint64_t abbrev = read_uleb128(r);
    if(!abbrev) {
        //printf("child end\n");
        return false;
    }
    struct dwarf_abbr *ab;
    if(abbrev >= kv_size(cu->acu->abbrs) ||
       (ab = &kv_A(cu->acu->abbrs, abbrev), !ab->tag))
        panic("bad abbrev 0x%02llx\n", abbrev);
    *node = (struct dwarf_node) {0};
    node->tag = ab->tag;
    //printf("abbrev=0x%llx tag=0x%02llx children=%d\n", abbrev, ab->tag, ab->has_children);
    for(struct dwarf_cached_attr *ca = ab->attrs; ca->form; ca++) {
        char crap[16];
        void *p = ca->node_offset == 0 ? crap : (void *) node + ca->node_offset;
        uint64_t blocklen;
        //printf("  name=0x%02x form=0x%02x\n", ca->name, ca->form);
        switch(ca->form) {
        case DW_FORM_strp:
        {
            //printf("node_offset=%x\n", ca->node_offset);
            uint64_t debug_str_offset = read_addr(cu);
            assert(debug_str_offset < debug_str.end - debug_str.ptr);
            *(const char **) p = debug_str.ptr + debug_str_offset;
            break;
        }
        case DW_FORM_string:
            *(const char **) p = read_cstr(r).ptr;
            break;

        case DW_FORM_data1:
        case DW_FORM_ref1:
            *(uint64_t *) p = read_t(uint8_t, r);
            break;
        case DW_FORM_data2:
        case DW_FORM_ref2:
            *(uint64_t *) p = read_t(uint16_t, r);
            break;
        case DW_FORM_data4:
        case DW_FORM_ref4:
            *(uint64_t *) p = read_t(uint32_t, r);
            break;
        case DW_FORM_data8:
        case DW_FORM_ref8:
            *(uint64_t *) p = read_t(uint64_t, r);
            break;
        case DW_FORM_udata:
        case DW_FORM_ref_udata:
            *(uint64_t *) p = read_uleb128(r);
            break;
        case DW_FORM_sdata:
            *(int64_t *) p = read_sleb128(r);
            break;
        case DW_FORM_addr:
            *(uint64_t *) p = read_addr(cu);
            break;
        case DW_FORM_block1:
            blocklen = read_t(uint8_t, r);
            goto block;
        case DW_FORM_block2:
            blocklen = read_t(uint16_t, r);
            goto block;
        case DW_FORM_block4:
            blocklen = read_t(uint32_t, r);
            goto block;
        case DW_FORM_block:
            blocklen = read_uleb128(r);
            goto block;
        block: {
            struct reader *pr = p;
            pr->ptr = read_bytes(r, blocklen); 
            pr->end = r->ptr;
            break;
        }
        case DW_FORM_flag:
            *(bool *) p = read_t(uint8_t, r);
            break;
        default:
            // should have been checked
            assert(0);
        }
    }
    return true;
}

static void parse_debug_info_header(struct cu_ctx *cu) {
    uint64_t abbrev_offset = read_addr(cu);
    khiter_t k = kh_get(abbr_cu, &dwarf_abbr_cus, abbrev_offset);
    assert(k != kh_end(&dwarf_abbr_cus));
    cu->acu = &kh_value(&dwarf_abbr_cus, k);
    UNUSED uint8_t addr_bytes = read_t(uint8_t, &cu->r);
}

static void parse_cu_header(struct cu_ctx *cu, struct reader *r) {
    cu->is64 = false;
    uint64_t length = read_t(uint32_t, r);
    if(length == 0xffffffff) {
        length = read_t(uint64_t, r);
        cu->is64 = true;
    }
    void *ptr = r->ptr;
    cu->full_r = (struct reader) {ptr - 4, ptr + length};
    UNUSED uint16_t version = read_t(uint16_t, r);
    assert(version >= 2 && version <= 10);
    read_bytes(r, length - 2);
    cu->r = reader_slice_to_end(cu->full_r, 6);
}

static void parse_all_cus(struct reader r, void (*action)(struct cu_ctx *cu, void *context), void *context) {
    while(r.ptr != r.end) {
        struct cu_ctx cu;
        parse_cu_header(&cu, &r);
        action(&cu, context);
    }
}

static void debug_pubx_cu_to_json(struct cu_ctx *cu, void *_tj) {
    struct tjson *tj = _tj;
    struct cu_ctx debug_info_cu;
    uint64_t debug_info_offset = read_addr(cu);
    uint64_t debug_info_size = read_addr(cu);
    struct reader debug_info_r = reader_slice(debug_info, debug_info_offset, debug_info_size);
    parse_cu_header(&debug_info_cu, &debug_info_r);
    parse_debug_info_header(&debug_info_cu);
    while(1) {
        uint64_t die_offset = read_addr(cu);
        if(!die_offset) break;
        UNUSED struct reader myname = read_cstr(&cu->r);
        debug_info_cu.r = reader_slice_to_end(debug_info_cu.full_r, die_offset);
        struct dwarf_node node;
        assert(parse_die(&debug_info_cu, &node));

        tjson_dict_key(tj, name.ptr);
        tjson_dict_start(tj);
            tjson_dict_key(tj, "vtable");
            tjson_list_start(tj);
            tjson_list_end(tj);
            tjson_dict_key(tj, "members");
            tjson_list_start(tj);
                
            tjson_list_end(tj);
        tjson_dict_end(tj);
    }
}

static void parse_debug_abbrev(struct reader r) {
    void *orig_ptr = r.ptr;
    while(r.ptr != r.end) {
        size_t offset = r.ptr - orig_ptr;
        int _;
        khiter_t k = kh_put(abbr_cu, &dwarf_abbr_cus, offset, &_);
        struct dwarf_abbr_cu *acu = &kh_value(&dwarf_abbr_cus, k);
        kv_init(acu->abbrs);

        while (1) {
            uint64_t abbrev = read_uleb128(&r);
            if(!abbrev) {
                break;
            }
            uint64_t tag = read_uleb128(&r);
            uint8_t has_children = read_t(uint8_t, &r);
            kvec_t(struct dwarf_cached_attr) cas;
            kv_init(cas);
            while(1) {
                uint64_t attr_name = read_uleb128(&r);
                uint64_t attr_form = read_uleb128(&r);
                if(attr_name == 0 && attr_form == 0) break;
                struct dwarf_cached_attr ca;
                ca.name = attr_name;
                ca.form = attr_form;

                // we'll need to be able to skip it in any case
                switch(attr_form) {
                case DW_FORM_strp:
                case DW_FORM_string:

                case DW_FORM_ref1:
                case DW_FORM_ref2:
                case DW_FORM_ref4:
                case DW_FORM_ref8:
                case DW_FORM_ref_udata:
                case DW_FORM_ref_addr:

                case DW_FORM_data1:
                case DW_FORM_data2:
                case DW_FORM_data4:
                case DW_FORM_data8:
                case DW_FORM_udata:
                case DW_FORM_sdata:
                case DW_FORM_addr:

                case DW_FORM_block1:
                case DW_FORM_block2:
                case DW_FORM_block4:
                case DW_FORM_block:

                case DW_FORM_flag:
                    break;
                default:
                    panic("unknown form 0x%02llx for attr 0x%02llx\n", attr_form, attr_name);
                }

                switch(attr_name) {
                case DW_AT_name:
                    ca.node_offset = offsetof(struct dwarf_node, at_name);
                    switch(attr_form) {
                    case DW_FORM_strp:
                    case DW_FORM_string:
                        break;
                    default:
                        goto bad;
                    }
                    break;
                case DW_AT_type:
                    ca.node_offset = offsetof(struct dwarf_node, at_type);
                    switch(attr_form) {
                    case DW_FORM_ref1:
                    case DW_FORM_ref2:
                    case DW_FORM_ref4:
                    case DW_FORM_ref8:
                    case DW_FORM_ref_udata:
                    case DW_FORM_ref_addr:
                        break;
                    default:
                        goto bad;
                    }
                    break;
                case DW_AT_byte_size:
                    ca.node_offset = offsetof(struct dwarf_node, at_byte_size);
                    switch(attr_form) {
                    case DW_FORM_data1:
                    case DW_FORM_data2:
                    case DW_FORM_data4:
                    case DW_FORM_data8:
                    case DW_FORM_udata:
                    case DW_FORM_sdata:
                    case DW_FORM_addr:
                        break;
                    default:
                        goto bad;
                    }
                    break;
                case DW_AT_data_member_location:
                    ca.node_offset = offsetof(struct dwarf_node, at_data_member_location);
                    switch(attr_form) {
                    case DW_FORM_block1:
                    case DW_FORM_block2:
                    case DW_FORM_block4:
                    case DW_FORM_block:
                        break;
                    default:
                        goto bad;
                    }
                    break;

                default:
                    ca.node_offset = 0;
                    break;
                }

                kv_push(struct dwarf_cached_attr, cas, ca);
                continue;

                bad:
                panic("inappropriate form 0x%02llx for attr 0x%02llx\n", attr_form, attr_name);
            }

            kv_push(struct dwarf_cached_attr, cas, ((struct dwarf_cached_attr) {0, 0}));
            struct dwarf_abbr ab;
            ab.has_children = has_children;
            ab.tag = tag;
            ab.attrs = cas.a;
            *kv_ap(struct dwarf_abbr, acu->abbrs, abbrev) = ab;
        }
    }
}

int main(int argc, char **argv) {
    int fd = open(argv[1], O_RDONLY);
    assert(fd != -1);
    off_t off = lseek(fd, 0, SEEK_END);
    size_t size = off;
    assert(off == size);
    void *file_map = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
    assert(file_map != MAP_FAILED);

    assert(size >= 5);
    const char *testhdr = file_map;
    assert(!memcmp(testhdr, ELFMAG, 4));

    struct reader debug_types = {0}, debug_abbrev = {0}, debug_pubtypes = {0};

    switch(testhdr[EI_CLASS]) {
#define CASES(text...) \
    case ELFCLASS32: { \
        typedef Elf32_Ehdr ehdr; \
        typedef Elf32_Shdr shdr; \
        text \
        break; \
    } \
    case ELFCLASS64: { \
        typedef Elf64_Ehdr ehdr; \
        typedef Elf64_Shdr shdr; \
        text \
        break; \
    }
    CASES(
        assert(sizeof(ehdr) <= size);
        ehdr *eh = file_map;
        assert(sadd64(eh->e_shoff, smul64(eh->e_shnum, eh->e_shentsize)) <= size);
        assert(eh->e_shstrndx <= eh->e_shnum);
        shdr *strsh = (void *) ((char *) file_map + eh->e_shoff + eh->e_shstrndx * eh->e_shentsize);

        for(int i = 0; i < eh->e_shnum; i++) {
            shdr *sh = (void *) ((char *) file_map + eh->e_shoff + i * eh->e_shentsize);
            assert(sh->sh_name < strsh->sh_size);
            uint64_t name_off = sadd64(sh->sh_name, strsh->sh_offset);
            assert(name_off < size);
            const char *name = (char *) file_map + name_off;
            size_t name_size = size - name_off;
            struct reader *reader;
            if(!strncmp(name, ".debug_abbrev", name_size)) {
                reader = &debug_abbrev;
            } else if(!strncmp(name, ".debug_info", name_size)) {
                reader = &debug_info;
            } else if(!strncmp(name, ".debug_types", name_size)) {
                reader = &debug_types;
            } else if(!strncmp(name, ".debug_pubtypes", name_size)) {
                reader = &debug_pubtypes;
            } else if(!strncmp(name, ".debug_str", name_size)) {
                reader = &debug_str;
            } else {
                continue;
            }
            assert(sadd64(sh->sh_offset, sh->sh_size) <= size);
            reader->ptr = (char *) file_map + sh->sh_offset;
            reader->end = reader->ptr + sh->sh_size;
        }
    )

    default:
        assert(false);
    }

    assert(debug_abbrev.ptr);
    parse_debug_abbrev(debug_abbrev);

    struct tjson tj = {stdout};
    tjson_dict_start(&tj);
    parse_all_cus(debug_pubtypes, debug_pubx_cu_to_json, &tj);
    tjson_dict_end(&tj);
}
