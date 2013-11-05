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

enum {
    AFL_NAME,
    AFL_TYPE,
    AFL_SPECIFICATION,
    AFL_SIBLING,
    AFL_BYTE_SIZE,
    AFL_DATA_MEMBER_LOCATION,
    AFL_VTABLE_ELEM_LOCATION
};

struct dwarf_node {
    uint64_t tag;
    bool has_children;
    uint64_t uid;
    uint64_t flag;
    const char *at_name;
    uint64_t at_type;
    uint64_t at_specification;
    uint64_t at_sibling;
    uint64_t at_byte_size;
    struct reader at_data_member_location;
    struct reader at_vtable_elem_location;
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
    uint8_t flag;
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

KHASH_SET_INIT_STR(strset)

struct export_ctx {
    struct tjson tj;
    khash_t(strset) *seen;
};

KHASH_MAP_INIT_INT64(abbr_cu, struct dwarf_abbr_cu)
KHASH_MAP_INIT_INT64(ccp, const char *)
static khash_t(abbr_cu) dwarf_abbr_cus;
static struct reader debug_str, debug_info;
static void *entire_file_start;

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
    node->uid = r->ptr - entire_file_start;
    node->tag = ab->tag;
    node->has_children = ab->has_children;
    node->flag = ab->flag;
    //printf("abbrev=0x%llx tag=0x%02llx children=%d\n", abbrev, ab->tag, ab->has_children);
    for(struct dwarf_cached_attr *ca = ab->attrs; ca->form; ca++) {
        char crap[16];
        void *p;
        if(ca->node_offset != 0)
            p = (void *) node + ca->node_offset;
        else
            p = crap;

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
    struct reader oldr = r;
    uint64_t count = 0;
    while(r.ptr != r.end) {
        struct cu_ctx cu;
        parse_cu_header(&cu, &r);
        count++;
    }
    r = oldr;
    uint64_t i = 0;
    while(r.ptr != r.end) {
        if(i % 100 == 0)
            fprintf(stderr, "[%llu/%llu]\n", i, count);
        i++;
        struct cu_ctx cu;
        parse_cu_header(&cu, &r);
        action(&cu, context);
    }
}

// also gets the size
static char *get_full_type_name(struct cu_ctx *cu, khash_t(ccp) *name_map, uint64_t offset, bool *must_free_p, size_t *sizep) {
    // i should probably have a string library.
    kvec_t(char) prefix = {0}, suffix = {0};
    char *base;
    bool first = true;
    while(1) {
        cu->r = reader_slice_to_end(cu->full_r, offset);
        struct dwarf_node node;
        assert(parse_die(cu, &node));
        if(first) {
            *sizep = (node.flag & (1 << AFL_BYTE_SIZE)) ? node.at_byte_size : -1;
            first = false;
        }
        if(!(node.flag & (1 << AFL_TYPE)) || node.tag == DW_TAG_typedef) {
            if(node.flag & (1 << AFL_SPECIFICATION)) {
                // get a better name
                offset = node.at_specification;
                continue;
            }
            khiter_t k = kh_get(ccp, name_map, offset);
            if(k != kh_end(name_map))
                base = (char *) kh_value(name_map, k);
            else
                base = "?";
            break;
        }
        offset = node.at_type;
        #define ADD_PARENS \
            if(!kv_size(prefix) || kv_A(prefix, 0) != '(' || kv_A(suffix, 0) != ')') { \
                kv_push(char, prefix, '('); \
                kv_push(char, suffix, ')'); \
            }
        switch(node.tag) {
        case DW_TAG_const_type:
        case DW_TAG_volatile_type:
            break;
        case DW_TAG_pointer_type:
            kv_push(char, prefix, '*');
            break;
        case DW_TAG_reference_type:
            kv_push(char, prefix, '&');
            break;
        case DW_TAG_array_type:
            ADD_PARENS;
            // whatever
            kv_push(char, suffix, '[');
            kv_push(char, suffix, ']');
            break;
        case DW_TAG_subroutine_type: {
            kv_push(char, prefix, '*');
            kv_push(char, prefix, '(');
            kv_push(char, suffix, ')');
            kv_push(char, suffix, '(');
            bool firstarg = true;
            struct dwarf_node subnode;
            if(node.has_children)
            while(parse_die(cu, &subnode)) {
                if(!(subnode.flag & (1 << AFL_TYPE))) continue;
                if(!firstarg) {
                    kv_push(char, suffix, ',');
                    kv_push(char, suffix, ' ');
                }
                firstarg = false;
                bool must_free;
                struct reader old = cu->r;
                size_t ignsize;
                char *argtype = get_full_type_name(cu, name_map, subnode.at_type, &must_free, &ignsize);
                cu->r = old;
                kv_insert_a(char, suffix, kv_size(suffix), argtype, strlen(argtype));
                if(must_free) free(argtype);
            }
            kv_push(char, suffix, ')');
            break;
        }
        default:
            panic("unknown tag 0x%02llx in type\n", node.tag);
        }
    }
    if(kv_size(prefix) == 0 && kv_size(suffix) == 0) {
        *must_free_p = false;
        return base;
    }
    kvec_t(char) result = {0};
    kv_insert_a(char, result, kv_size(result), base, strlen(base));
    kv_push(char, result, ' ');
    for(size_t i = kv_size(prefix); i > 0; i--)
        kv_push(char, result, kv_A(prefix, i - 1));
    kv_insert_a(char, result, kv_size(result), suffix.a, kv_size(suffix));
    kv_push(char, result, '\0');
    *must_free_p = true;
    return result.a;
}

static uint64_t loc_to_offset(struct reader loc) {
    uint8_t code = read_t(uint8_t, &loc);
    if(code == DW_OP_plus_uconst || code == DW_OP_constu)
        return read_uleb128(&loc);
    else
        return -1;
}

static void die_to_json(struct export_ctx *ec, struct cu_ctx *cu, struct dwarf_node *node, khash_t(ccp) *name_map, const char *myname) {
    struct tjson *tj = &ec->tj;
    if(!(node->tag == DW_TAG_class_type || node->tag == DW_TAG_structure_type))
        return;
    if(!(node->flag & (1 << AFL_BYTE_SIZE))) {
        // partial
        return;
    }

    int putret;
    kh_put(strset, ec->seen, myname, &putret);
    if(putret <= 0) {
        // already seen
        return;
    }

    tjson_dict_key(tj, myname);
    tjson_dict_start(tj);
        struct vtable_elem {
            const char *name;
            uint64_t offset;
        };
        kvec_t(struct vtable_elem) vtable_elems = {0};
        tjson_dict_key(tj, "size");
        tjson_num(tj, node->at_byte_size);
        tjson_dict_key(tj, "members");
        tjson_list_start(tj);
        struct dwarf_node subnode;
        if(node->has_children)
        while(parse_die(cu, &subnode)) {
            struct reader next = cu->r;

            const char *name;
            if(subnode.tag == DW_TAG_inheritance)
                name = "_parent";
            else if(subnode.flag & (1 << AFL_NAME))
                name = subnode.at_name;
            else
                name = "<anon>";

            switch(subnode.tag) {
            case DW_TAG_member:
            case DW_TAG_inheritance: {
                bool free_typename;
                size_t size;
                char *typename = get_full_type_name(cu, name_map, subnode.at_type, &free_typename, &size);

                tjson_dict_start(tj);
                    tjson_dict_key(tj, "name");
                    tjson_str(tj, name);
                    if(subnode.flag & (1 << AFL_DATA_MEMBER_LOCATION)) {
                        uint64_t offset = loc_to_offset(subnode.at_data_member_location);

                        if(offset != -1) {
                            tjson_dict_key(tj, "offset");
                            tjson_num(tj, offset);
                        }
                    }
                    if(size != -1) {
                        tjson_dict_key(tj, "size");
                        tjson_num(tj, size);
                    }
                    tjson_dict_key(tj, "type");
                    tjson_str(tj, typename);
                tjson_dict_end(tj);

                if(free_typename) free(typename);
                break;
            }

            default:
                if(subnode.flag & (1 << AFL_VTABLE_ELEM_LOCATION)) {
                    uint64_t offset = loc_to_offset(subnode.at_vtable_elem_location);
                    if(offset != -1)
                        kv_push(struct vtable_elem, vtable_elems, ((struct vtable_elem) {name, offset}));
                }
            }

            if(subnode.flag & (1 << AFL_SIBLING))
                next = reader_slice_to_end(cu->full_r, subnode.at_sibling);
            cu->r = next;
        }
        tjson_list_end(tj);
        if(kv_size(vtable_elems)) {
            tjson_dict_key(tj, "vtable");
            tjson_dict_start(tj);
            char key[64];
            for(size_t i = 0; i < kv_size(vtable_elems); i++) {
                struct vtable_elem ve = kv_A(vtable_elems, i);
                snprintf(key, sizeof(key), "%llu", ve.offset);
                tjson_dict_key(tj, key);
                tjson_str(tj, ve.name);
            }
            tjson_dict_end(tj);
            kv_destroy(vtable_elems);
        }
    tjson_dict_end(tj);
}

static void debug_pubtypes_cu_to_json(struct cu_ctx *cu, void *_ec) {
    struct export_ctx *ec = _ec;
    struct cu_ctx debug_info_cu;
    uint64_t debug_info_offset = read_addr(cu);
    uint64_t debug_info_size = read_addr(cu);
    struct reader debug_info_r = reader_slice(debug_info, debug_info_offset, debug_info_size);
    parse_cu_header(&debug_info_cu, &debug_info_r);
    parse_debug_info_header(&debug_info_cu);
    struct reader oldr = cu->r;
    khash_t(ccp) *name_map = kh_init(ccp);

    // get the qualified names
    while(1) {
        uint64_t die_offset = read_addr(cu);
        if(!die_offset) break;
        struct reader myname = read_cstr(&cu->r);
        int _;
        kh_value(name_map, kh_put(ccp, name_map, die_offset, &_)) = myname.ptr;
    }

    cu->r = oldr;
    while(1) {
        uint64_t die_offset = read_addr(cu);
        if(!die_offset) break;
        struct reader myname = read_cstr(&cu->r);
        debug_info_cu.r = reader_slice_to_end(debug_info_cu.full_r, die_offset);
        struct dwarf_node node;
        assert(parse_die(&debug_info_cu, &node));
        die_to_json(ec, &debug_info_cu, &node, name_map, myname.ptr);
    }

    kh_destroy(ccp, name_map);
}

static void debug_info_cu_to_json(struct cu_ctx *restrict cu, void *_ec) {
    // basically, brute force
    parse_debug_info_header(cu);
    struct export_ctx *ec = _ec;
    struct reader oldr = cu->r;
    khash_t(ccp) *name_map = kh_init(ccp);
    kvec_t(char) namespace = {0};
    kvec_t(size_t) namespace_lens = {0};

    // pass 0: fill in the names
    // pass 1: print
    for (int pass = 0; pass <= 1; pass++) {
        int depth = 0;
        while(cu->r.ptr != cu->r.end) {
            struct dwarf_node node;
            uint64_t offset = cu->r.ptr - cu->full_r.ptr;
            if(!parse_die(cu, &node)) {
                assert(--depth >= 0);
                namespace.n = kv_pop(namespace_lens);
                continue;
            }

            switch(node.tag) {
            case DW_TAG_class_type:
            case DW_TAG_structure_type:
            case DW_TAG_typedef:
            case DW_TAG_base_type:
                if(pass == 0) {
                    int _;
                    char *name;
                    asprintf(&name, "%.*s%s", (int) namespace.n, namespace.a, node.at_name);
                    kh_value(name_map, kh_put(ccp, name_map, offset, &_)) = name;
                } else {
                    die_to_json(ec, cu, &node, name_map, node.at_name);
                }
                break;
            case DW_TAG_namespace: {
                if(pass == 0) {
                    // parse children
                    const char *nsname = (node.flag & (1 << AFL_NAME)) ? node.at_name : "<anon>";
                    kv_push(size_t, namespace_lens, kv_size(namespace));
                    kv_insert_a(char, namespace, kv_size(namespace), nsname, strlen(nsname));
                    kv_insert_a(char, namespace, kv_size(namespace), "::", 2);
                    depth++;
                    continue;
                }
                break;
            }
            }

            // skip children
            if(node.flag & (1 << AFL_SIBLING)) {
                cu->r = reader_slice_to_end(cu->full_r, node.at_sibling);
            } else if(node.has_children) {
                kv_push(size_t, namespace_lens, kv_size(namespace));
                depth++;
            }
        }
        cu->r = oldr;
    }

    // my hash table does this better.
    const char *name;
    kh_foreach_value(name_map, name, free((char *) name));
    kh_destroy(ccp, name_map);
}

static void parse_debug_abbrev(struct reader r) {
    void *orig_ptr = r.ptr;
    while(r.ptr != r.end) {
        size_t offset = r.ptr - orig_ptr;
        int _;
        khiter_t k = kh_put(abbr_cu, &dwarf_abbr_cus, offset, &_);
        struct dwarf_abbr_cu *acu = &kh_value(&dwarf_abbr_cus, k);
        kv_init(acu->abbrs);

        while(1) {
            uint64_t abbrev = read_uleb128(&r);
            if(!abbrev) {
                break;
            }
            uint64_t tag = read_uleb128(&r);
            uint8_t has_children = read_t(uint8_t, &r);
            kvec_t(struct dwarf_cached_attr) cas;
            kv_init(cas);
            struct dwarf_abbr ab;
            ab.has_children = has_children;
            ab.tag = tag;
            ab.flag = 0;
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
                //case DW_FORM_ref_addr:

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
                    ab.flag |= 1 << AFL_NAME;
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
                    ab.flag |= 1 << AFL_TYPE;
                    goto ref;
                case DW_AT_specification:
                    ca.node_offset = offsetof(struct dwarf_node, at_specification);
                    ab.flag |= 1 << AFL_SPECIFICATION;
                    goto ref;
                case DW_AT_sibling:
                    ca.node_offset = offsetof(struct dwarf_node, at_sibling);
                    ab.flag |= 1 << AFL_SIBLING;
                    goto ref;
                ref:
                    switch(attr_form) {
                    case DW_FORM_ref1:
                    case DW_FORM_ref2:
                    case DW_FORM_ref4:
                    case DW_FORM_ref8:
                    case DW_FORM_ref_udata:
                    //case DW_FORM_ref_addr:
                        break;
                    default:
                        goto bad;
                    }
                    break;
                case DW_AT_byte_size:
                    ca.node_offset = offsetof(struct dwarf_node, at_byte_size);
                    ab.flag |= 1 << AFL_BYTE_SIZE;
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
                    ab.flag |= 1 << AFL_DATA_MEMBER_LOCATION;
                    goto block;
                case DW_AT_vtable_elem_location:
                    ca.node_offset = offsetof(struct dwarf_node, at_vtable_elem_location);
                    ab.flag |= 1 << AFL_VTABLE_ELEM_LOCATION;
                    goto block;
                block:
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
            ab.attrs = cas.a;
            *kv_ap(struct dwarf_abbr, acu->abbrs, abbrev) = ab;
        }
    }
}

int main(int argc, char **argv) {
    set_block_buffered(stdout);

    int fd = open(argv[1], O_RDONLY);
    assert(fd != -1);
    off_t off = lseek(fd, 0, SEEK_END);
    size_t size = off;
    assert(off == size);
    void *file_map = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
    assert(file_map != MAP_FAILED);

    entire_file_start = file_map;

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

    struct export_ctx ec = {{stdout}, kh_init(strset)};
    tjson_dict_start(&ec.tj);
    if(debug_pubtypes.ptr) {
        parse_all_cus(debug_pubtypes, debug_pubtypes_cu_to_json, &ec);
    } else {
        parse_all_cus(debug_info, debug_info_cu_to_json, &ec);
    }
    tjson_dict_end(&ec.tj);
    putchar('\n');
}
