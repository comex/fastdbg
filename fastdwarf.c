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
#include "mach-o/loader.h"
#include "common.h"
#include "klib/kvec.h"
#include "klib/khash.h"

/* '<,'>s!\([A-Z][^ ]*\)  *=  *\([^, ]*\).*!x(\1, \2) \ */
#define enum_dwarf_tag(x) \
    x(DW_TAG_padding, 0x00) \
    x(DW_TAG_array_type, 0x01) \
    x(DW_TAG_class_type, 0x02) \
    x(DW_TAG_entry_point, 0x03) \
    x(DW_TAG_enumeration_type, 0x04) \
    x(DW_TAG_formal_parameter, 0x05) \
    x(DW_TAG_imported_declaration, 0x08) \
    x(DW_TAG_label, 0x0a) \
    x(DW_TAG_lexical_block, 0x0b) \
    x(DW_TAG_member, 0x0d) \
    x(DW_TAG_pointer_type, 0x0f) \
    x(DW_TAG_reference_type, 0x10) \
    x(DW_TAG_compile_unit, 0x11) \
    x(DW_TAG_string_type, 0x12) \
    x(DW_TAG_structure_type, 0x13) \
    x(DW_TAG_subroutine_type, 0x15) \
    x(DW_TAG_typedef, 0x16) \
    x(DW_TAG_union_type, 0x17) \
    x(DW_TAG_unspecified_parameters, 0x18) \
    x(DW_TAG_variant, 0x19) \
    x(DW_TAG_common_block, 0x1a) \
    x(DW_TAG_common_inclusion, 0x1b) \
    x(DW_TAG_inheritance, 0x1c) \
    x(DW_TAG_inlined_subroutine, 0x1d) \
    x(DW_TAG_module, 0x1e) \
    x(DW_TAG_ptr_to_member_type, 0x1f) \
    x(DW_TAG_set_type, 0x20) \
    x(DW_TAG_subrange_type, 0x21) \
    x(DW_TAG_with_stmt, 0x22) \
    x(DW_TAG_access_declaration, 0x23) \
    x(DW_TAG_base_type, 0x24) \
    x(DW_TAG_catch_block, 0x25) \
    x(DW_TAG_const_type, 0x26) \
    x(DW_TAG_constant, 0x27) \
    x(DW_TAG_enumerator, 0x28) \
    x(DW_TAG_file_type, 0x29) \
    x(DW_TAG_friend, 0x2a) \
    x(DW_TAG_namelist, 0x2b) \
    x(DW_TAG_namelist_item, 0x2c) \
    x(DW_TAG_packed_type, 0x2d) \
    x(DW_TAG_subprogram, 0x2e) \
    x(DW_TAG_template_type_param, 0x2f) \
    x(DW_TAG_template_value_param, 0x30) \
    x(DW_TAG_thrown_type, 0x31) \
    x(DW_TAG_try_block, 0x32) \
    x(DW_TAG_variant_part, 0x33) \
    x(DW_TAG_variable, 0x34) \
    x(DW_TAG_volatile_type, 0x35) \
    x(DW_TAG_dwarf_procedure, 0x36) \
    x(DW_TAG_restrict_type, 0x37) \
    x(DW_TAG_interface_type, 0x38) \
    x(DW_TAG_namespace, 0x39) \
    x(DW_TAG_imported_module, 0x3a) \
    x(DW_TAG_unspecified_type, 0x3b) \
    x(DW_TAG_partial_unit, 0x3c) \
    x(DW_TAG_imported_unit, 0x3d) \
    x(DW_TAG_condition, 0x3f) \
    x(DW_TAG_shared_type, 0x40) \
    x(DW_TAG_format_label, 0x4101) \
    x(DW_TAG_function_template, 0x4102) \
    x(DW_TAG_class_template, 0x4103) \
    x(DW_TAG_GNU_BINCL, 0x4104) \
    x(DW_TAG_GNU_EINCL, 0x4105)

#define enum_dwarf_form(x) \
    x(DW_FORM_addr, 0x01) \
    x(DW_FORM_block2, 0x03) \
    x(DW_FORM_block4, 0x04) \
    x(DW_FORM_data2, 0x05) \
    x(DW_FORM_data4, 0x06) \
    x(DW_FORM_data8, 0x07) \
    x(DW_FORM_string, 0x08) \
    x(DW_FORM_block, 0x09) \
    x(DW_FORM_block1, 0x0a) \
    x(DW_FORM_data1, 0x0b) \
    x(DW_FORM_flag, 0x0c) \
    x(DW_FORM_sdata, 0x0d) \
    x(DW_FORM_strp, 0x0e) \
    x(DW_FORM_udata, 0x0f) \
    x(DW_FORM_ref_addr, 0x10) \
    x(DW_FORM_ref1, 0x11) \
    x(DW_FORM_ref2, 0x12) \
    x(DW_FORM_ref4, 0x13) \
    x(DW_FORM_ref8, 0x14) \
    x(DW_FORM_ref_udata, 0x15) \
    x(DW_FORM_indirect, 0x16) \
    x(DW_FORM_secoffset, 0x17) \
    x(DW_FORM_exprloc, 0x18) \
    x(DW_FORM_flag_present, 0x19) \
    x(DW_FORM_ref_sig8, 0x20)

#define enum_dwarf_at(x) \
    x(DW_AT_sibling, 0x01) \
    x(DW_AT_location, 0x02) \
    x(DW_AT_name, 0x03) \
    x(DW_AT_ordering, 0x09) \
    x(DW_AT_subscr_data, 0x0a) \
    x(DW_AT_byte_size, 0x0b) \
    x(DW_AT_bit_offset, 0x0c) \
    x(DW_AT_bit_size, 0x0d) \
    x(DW_AT_element_list, 0x0f) \
    x(DW_AT_stmt_list, 0x10) \
    x(DW_AT_low_pc, 0x11) \
    x(DW_AT_high_pc, 0x12) \
    x(DW_AT_language, 0x13) \
    x(DW_AT_member, 0x14) \
    x(DW_AT_discr, 0x15) \
    x(DW_AT_discr_value, 0x16) \
    x(DW_AT_visibility, 0x17) \
    x(DW_AT_import, 0x18) \
    x(DW_AT_string_length, 0x19) \
    x(DW_AT_common_reference, 0x1a) \
    x(DW_AT_comp_dir, 0x1b) \
    x(DW_AT_const_value, 0x1c) \
    x(DW_AT_containing_type, 0x1d) \
    x(DW_AT_default_value, 0x1e) \
    x(DW_AT_inline, 0x20) \
    x(DW_AT_is_optional, 0x21) \
    x(DW_AT_lower_bound, 0x22) \
    x(DW_AT_producer, 0x25) \
    x(DW_AT_prototyped, 0x27) \
    x(DW_AT_return_addr, 0x2a) \
    x(DW_AT_start_scope, 0x2c) \
    x(DW_AT_stride_size, 0x2e) \
    x(DW_AT_upper_bound, 0x2f) \
    x(DW_AT_abstract_origin, 0x31) \
    x(DW_AT_accessibility, 0x32) \
    x(DW_AT_address_class, 0x33) \
    x(DW_AT_artificial, 0x34) \
    x(DW_AT_base_types, 0x35) \
    x(DW_AT_calling_convention, 0x36) \
    x(DW_AT_count, 0x37) \
    x(DW_AT_data_member_location, 0x38) \
    x(DW_AT_decl_column, 0x39) \
    x(DW_AT_decl_file, 0x3a) \
    x(DW_AT_decl_line, 0x3b) \
    x(DW_AT_declaration, 0x3c) \
    x(DW_AT_discr_list, 0x3d) \
    x(DW_AT_encoding, 0x3e) \
    x(DW_AT_external, 0x3f) \
    x(DW_AT_frame_base, 0x40) \
    x(DW_AT_friend, 0x41) \
    x(DW_AT_identifier_case, 0x42) \
    x(DW_AT_macro_info, 0x43) \
    x(DW_AT_namelist_items, 0x44) \
    x(DW_AT_priority, 0x45) \
    x(DW_AT_segment, 0x46) \
    x(DW_AT_specification, 0x47) \
    x(DW_AT_static_link, 0x48) \
    x(DW_AT_type, 0x49) \
    x(DW_AT_use_location, 0x4a) \
    x(DW_AT_variable_parameter, 0x4b) \
    x(DW_AT_virtuality, 0x4c) \
    x(DW_AT_vtable_elem_location, 0x4d) \
    x(DW_AT_allocated, 0x4e) \
    x(DW_AT_associated, 0x4f) \
    x(DW_AT_data_location, 0x50) \
    x(DW_AT_stride, 0x51) \
    x(DW_AT_entry_pc, 0x52) \
    x(DW_AT_use_UTF8, 0x53) \
    x(DW_AT_extension, 0x54) \
    x(DW_AT_ranges, 0x55) \
    x(DW_AT_trampoline, 0x56) \
    x(DW_AT_call_column, 0x57) \
    x(DW_AT_call_file, 0x58) \
    x(DW_AT_call_line, 0x59) \
    x(DW_AT_description, 0x5a) \
    x(DW_AT_binary_scale, 0x5b) \
    x(DW_AT_decimal_scale, 0x5c) \
    x(DW_AT_small, 0x5d) \
    x(DW_AT_decimal_sign, 0x5e) \
    x(DW_AT_digit_count, 0x5f) \
    x(DW_AT_picture_string, 0x60) \
    x(DW_AT_mutable, 0x61) \
    x(DW_AT_threads_scaled, 0x62) \
    x(DW_AT_explicit, 0x63) \
    x(DW_AT_object_pointer, 0x64) \
    x(DW_AT_endianity, 0x65) \
    x(DW_AT_elemental, 0x66) \
    x(DW_AT_pure, 0x67) \
    x(DW_AT_recursive, 0x68) \
    x(DW_AT_sf_names, 0x2101) \
    x(DW_AT_src_info, 0x2102) \
    x(DW_AT_mac_info, 0x2103) \
    x(DW_AT_src_coords, 0x2104) \
    x(DW_AT_body_begin, 0x2105) \
    x(DW_AT_body_end, 0x2106) \
    x(DW_AT_GNU_vector, 0x2107)

enum {
    DW_OP_constu = 0x10,
    DW_OP_plus_uconst = 0x23,
};

#define _ENUM_ENTRY(name, val) name = val,
#define _ENUM_GETNAME(name, val) case name: return &#name[skip];
#define DEFINE_ENUM(c, name, prefix) \
    enum { \
        c(_ENUM_ENTRY) \
    }; \
    static const char *name##_name(uint64_t val) { \
        int skip = sizeof(prefix) - 1; \
        static char unkbuf[64]; \
        switch(val) { \
            c(_ENUM_GETNAME) \
            default: \
                sprintf(unkbuf, "<unknown %llx>", val); \
                return unkbuf; \
        } \
    }

DEFINE_ENUM(enum_dwarf_tag, dwarf_tag, "DW_TAG_")
DEFINE_ENUM(enum_dwarf_form, dwarf_form, "DW_FORM_")
DEFINE_ENUM(enum_dwarf_at, dwarf_at, "DW_AT_")

#define FORM_DATA_AS_LOCATION 0x80

enum {
    AFL_NAME,
    AFL_TYPE,
    AFL_SPECIFICATION,
    AFL_SIBLING,
    AFL_BYTE_SIZE,
    AFL_DATA_MEMBER_LOCATION,
    AFL_VTABLE_ELEM_LOCATION,
};

struct dwarf_location {
    union {
        struct reader r;
        uint64_t constant;
    };
    bool is_constant;
};

struct dwarf_ref {
    bool is_ref_addr;
    uint64_t offset;
};

struct dwarf_node {
    uint32_t tag;
    bool has_children;
    uint32_t flag;
    uint64_t uid;
    const char *at_name;
    struct dwarf_ref at_type;
    struct dwarf_ref at_specification;
    struct dwarf_ref at_sibling;
    uint64_t at_byte_size;
    struct dwarf_location at_data_member_location;
    struct dwarf_location at_vtable_elem_location;
};

struct dwarf_cached_attr {
    uint8_t name; // just for reference
    uint8_t form;
    uint8_t node_offset;
};

struct dwarf_abbr {
    uint32_t tag;
    bool has_children;
    struct dwarf_cached_attr *attrs;
    uint32_t flag;
};

struct dwarf_abbr_cu {
    kvec_t(struct dwarf_abbr) abbrs;
};

typedef kvec_t(struct cu_ctx) cu_vec_t;
struct cu_ctx {
    struct reader full_r; // the entire CU
    struct reader r; // where we're reading now
    bool is64;
    uint16_t version;
    int addr_bytes;
    // debug_info
    struct dwarf_abbr_cu *acu;
    // debug_types
    uint64_t type_signature;
    uint64_t type_offset;

};

KHASH_SET_INIT_STR(strset)
KHASH_MAP_INIT_INT64(ccp, const char *)
KHASH_MAP_INIT_INT64(abbr_cu, struct dwarf_abbr_cu)

struct export_ctx {
    struct tjson tj;
    khash_t(strset) *seen;
    khash_t(ccp) *name_map;
    bool name_map_needs_mass_free;
};

static khash_t(abbr_cu) dwarf_abbr_cus;
static struct reader debug_str, debug_info;
static struct reader debug_types, debug_abbrev, debug_pubtypes, debug_pubnames;

static cu_vec_t debug_info_cus;//, debug_types_cus;

static void *file_map;
static size_t file_size;

static struct reader read_cstr(struct reader *r) {
    size_t len = strnlen(r->ptr, r->end - r->ptr);
    if(len == r->end - r->ptr)
        panic("read_cstr: no null terminator");
    void *ptr = r->ptr;
    r->ptr += len + 1;
    return (struct reader) {ptr, ptr + len};
}

// 64 bits in the "64-bit DWARF format", etc.
static uint64_t read_fmtbits(struct cu_ctx *cu) {
    return cu->is64 ? read_t(uint64_t, &cu->r) : read_t(uint32_t, &cu->r);
}

static uint64_t read_addr(struct cu_ctx *cu) {
    return cu->addr_bytes == 8 ? read_t(uint64_t, &cu->r) : read_t(uint32_t, &cu->r);
}

static void switch_to_dwarf_ref(struct cu_ctx *restrict *cup, struct reader *oldrp, struct dwarf_ref ref) {
    struct cu_ctx *cu = *cup;
    if(!ref.is_ref_addr) {
        cu->r = reader_slice_to_end(cu->full_r, ref.offset);
    } else {
        struct reader r = reader_slice_to_end(debug_info, ref.offset);
        void *ptr = r.ptr;
        cu_vec_t *v = &debug_info_cus;
        assert(v->n);
        ssize_t lo = 0, hi = v->n - 1;
        while(lo <= hi) {
            size_t mid = (lo + hi) / 2;
            //printf("%zu %zu %zu\n", lo, hi, mid);
            struct cu_ctx *ocu = &v->a[mid];
            struct reader s = ocu->full_r;
            //printf("?    %p %p %p\n", ptr, r.ptr, r.end);
            if(ptr >= s.ptr && ptr < s.end) {
                if(oldrp) {
                    cu->r = *oldrp;
                    struct reader oldr = ocu->r;
                    *oldrp = oldr;
                }
                ocu->r = r;
                *cup = ocu;
                return;
            } else if(ptr < s.ptr) {
                hi = mid - 1;
            } else if(ptr >= s.end) {
                lo = mid + 1;
            } else {
                assert(0);
            }

        }
        panic("ref_addr target not found (lo=%zu hi=%zu, n=%zu)\n", lo, hi, v->n);
    }
}
inline struct reader slice_ref_to_end(const struct cu_ctx *cu, struct dwarf_ref offset) {
    struct reader base = offset.is_ref_addr ? debug_info : cu->full_r;
    return reader_slice_to_end(base, offset.offset);
}

static void export_ctx_init(struct export_ctx *ec, size_t debug_info_size) {
    ec->tj = (struct tjson) {stdout};
    ec->seen = kh_init(strset);
    // a rough estimate to avoid rehashing
    kh_resize(strset, ec->seen, debug_info_size / 1500);
    ec->name_map = kh_init(ccp);
}

static void export_ctx_destroy(struct export_ctx *ec) {
    kh_destroy(strset, ec->seen);
    {
        // my hash table does this macro better.
        const char *name;
        kh_foreach_value(ec->name_map, name, free((char *) name));
    }
    kh_destroy(ccp, ec->name_map);
}

static void parse_attr(struct cu_ctx *cu, uint64_t form, void *p) {
    struct reader *r = &cu->r;
    uint64_t blocklen;
    struct dwarf_ref *pref = p;
    //printf("form=%s rp=%p\n", dwarf_form_name(form & ~FORM_DATA_AS_LOCATION), r->ptr);
    switch(form & ~FORM_DATA_AS_LOCATION) {
    case DW_FORM_strp:
    {
        //printf("node_offset=%x\n", ca->node_offset);
        uint64_t debug_str_offset = read_fmtbits(cu);
        //printf("%llx %llx\n", debug_str_offset, debug_str.end - debug_str.ptr);
        assert(debug_str_offset < debug_str.end - debug_str.ptr);
        *(const char **) p = debug_str.ptr + debug_str_offset;
        break;
    }
    case DW_FORM_string:
        *(const char **) p = read_cstr(r).ptr;
        break;

    case DW_FORM_data1:
        *(uint64_t *) p = read_t(uint8_t, r);
        break;
    case DW_FORM_data2:
        *(uint64_t *) p = read_t(uint16_t, r);
        break;
    case DW_FORM_data4:
        *(uint64_t *) p = read_t(uint32_t, r);
        break;
    case DW_FORM_data8:
        *(uint64_t *) p = read_t(uint64_t, r);
        break;
    case DW_FORM_udata:
        *(uint64_t *) p = read_uleb128(r);
        break;
    case DW_FORM_sdata:
        *(int64_t *) p = read_sleb128(r);
        break;
    case DW_FORM_addr:
        *(uint64_t *) p = read_addr(cu);
        break;
    case DW_FORM_secoffset:
        *(uint64_t *) p = read_fmtbits(cu);
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
    case DW_FORM_exprloc:
        blocklen = read_uleb128(r);
        goto block;
    block: {
        struct dwarf_location *loc = p;
        loc->is_constant = false;
        loc->r.ptr = read_bytes(r, blocklen);
        loc->r.end = r->ptr;
        break;
    }

    case DW_FORM_ref1:
        pref->is_ref_addr = false;
        pref->offset = read_t(uint8_t, r);
        break;
    case DW_FORM_ref2:
        pref->is_ref_addr = false;
        pref->offset = read_t(uint16_t, r);
        break;
    case DW_FORM_ref4:
        pref->is_ref_addr = false;
        pref->offset = read_t(uint32_t, r);
        break;
    case DW_FORM_ref_sig8: // we won't even notice
    case DW_FORM_ref8:
        pref->is_ref_addr = false;
        pref->offset = read_t(uint64_t, r);
        break;
    case DW_FORM_ref_udata:
        pref->is_ref_addr = false;
        pref->offset = read_uleb128(r);
        break;
    case DW_FORM_ref_addr:
        pref->is_ref_addr = true;
        pref->offset = cu->version >= 3 ? read_fmtbits(cu) : read_addr(cu);
        break;

    case DW_FORM_flag:
        *(bool *) p = read_t(uint8_t, r);
        break;
    case DW_FORM_flag_present:
        *(bool *) p = true;
        break;
    default:
        // should have been checked
        assert(0);
    }
    if(form & FORM_DATA_AS_LOCATION) {
        ((struct dwarf_location *) p)->is_constant = true;
    }
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
        panic("bad abbrev 0x%02llx (we probably got misaligned)\n", abbrev);
    memset(node, 0xff, sizeof(*node));
    node->uid = r->ptr - file_map;
    node->tag = ab->tag;
    node->has_children = ab->has_children;
    node->flag = ab->flag;
    //printf("abbrev=0x%llx tag=0x%02x children=%d\n", abbrev, ab->tag, ab->has_children);
    for(struct dwarf_cached_attr *ca = ab->attrs; ca->form; ca++) {
        char crap[64];
        void *p;
        if(ca->node_offset != 0)
            p = (void *) node + ca->node_offset;
        else
            p = crap;

        uint64_t form = ca->form;
        //printf("  name=0x%02x form=0x%02x\n", ca->name, ca->form);
        parse_attr(cu, form, p);
    }
    return true;
}

static void parse_debug_info_header(struct cu_ctx *cu) {
    uint64_t abbrev_offset = read_fmtbits(cu);
    khiter_t k = kh_get(abbr_cu, &dwarf_abbr_cus, abbrev_offset);
    assert(k != kh_end(&dwarf_abbr_cus));
    cu->acu = &kh_value(&dwarf_abbr_cus, k);
    cu->addr_bytes = read_t(uint8_t, &cu->r);
}

static void parse_debug_types_header(struct cu_ctx *cu) {
    cu->type_signature = read_t(uint64_t, &cu->r);
    cu->type_offset = read_fmtbits(cu);
}

static void parse_cu_header(struct cu_ctx *cu, struct reader *r) {
    uint64_t length = read_t(uint32_t, r);
    cu->is64 = false;
    if(length == 0xffffffff) {
        cu->is64 = true;
        length = read_t(uint64_t, r);
    }
    void *ptr = r->ptr;
    cu->full_r = (struct reader) {ptr - 4, ptr + length};
    uint16_t version = read_t(uint16_t, r);
    assert(version >= 2 && version <= 10);
    cu->version = version;
    read_bytes(r, length - 2);
    cu->r = reader_slice_to_end(cu->full_r, 6);
    cu->acu = NULL;
}

static void parse_all_cus(struct reader r, void (*action)(struct cu_ctx *cu, void *context), void *context) {
    while(r.ptr != r.end) {
        struct cu_ctx cu;
        parse_cu_header(&cu, &r);
        action(&cu, context);
    }
}

static void init_info_cu_vec(struct reader r, cu_vec_t *v) {
    while(r.ptr != r.end) {
        struct cu_ctx *cu = (kv_pushp(struct cu_ctx, *v));
        parse_cu_header(cu, &r);
        parse_debug_info_header(cu);
        //printf(">> %p\n", cu.full_r.ptr);
    }
}

// also gets the size
static char *get_full_type_name(struct cu_ctx *cu, khash_t(ccp) *name_map, struct dwarf_ref offset, bool *must_free_p, size_t *sizep) {
    // i should probably have a string library.
    struct reader oldr = cu->r;
    kvec_t(char) prefix = {0}, suffix = {0};
    char *base = NULL;
    char *res;
    bool free_base = false;
    bool first = true;
    while(1) {
        switch_to_dwarf_ref(&cu, &oldr, offset);
        struct dwarf_node node;
        //printf("GFTY> %d %llu\n", offset.is_ref_addr, offset.offset);
        void *ptr = cu->r.ptr;
        assert(parse_die(cu, &node));
        if(first) {
            *sizep = (node.flag & (1 << AFL_BYTE_SIZE)) ? node.at_byte_size : -1;
            first = false;
        }
        if(!(node.flag & (1 << AFL_TYPE))) {
            assert(ptr >= debug_info.ptr && ptr < debug_info.end);
            khiter_t k = kh_get(ccp, name_map, ptr - debug_info.ptr);
            if(k != kh_end(name_map))
                base = (char *) kh_value(name_map, k);
            if(node.flag & (1 << AFL_SPECIFICATION)) {
                offset = node.at_specification;
                continue;
            }
            if(!base && (node.flag & (1 << AFL_NAME))) {
                // this isn't good because it lacks a namespace - why don't we
                // have a name?
                asprintf(&base, "??::%s", node.at_name);
                free_base = true;
            }
            if(!base)
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
        case DW_TAG_typedef:
            first = true;
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
        case DW_TAG_ptr_to_member_type:
            base = "XXX ptm";
            goto b;
        case DW_TAG_subroutine_type: {
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
                size_t ignsize;
                char *argtype = get_full_type_name(cu, name_map, subnode.at_type, &must_free, &ignsize);
                kv_insert_a(char, suffix, kv_size(suffix), argtype, strlen(argtype));
                if(must_free) free(argtype);
            }
            kv_push(char, suffix, ')');
            break;
        }
        default:
            base = "?????"; goto b;
            panic("unknown tag 0x%02x in type\n", node.tag);
        }
    }
    b:
    if(kv_size(prefix) == 0 && kv_size(suffix) == 0) {
        *must_free_p = free_base;
        res = base;
        goto end;
    }
    kvec_t(char) result = {0};
    kv_insert_a(char, result, kv_size(result), base, strlen(base));
    kv_push(char, result, ' ');
    for(size_t i = kv_size(prefix); i > 0; i--)
        kv_push(char, result, kv_A(prefix, i - 1));
    kv_insert_a(char, result, kv_size(result), suffix.a, kv_size(suffix));
    kv_push(char, result, '\0');
    kv_destroy(prefix);
    kv_destroy(suffix);
    *must_free_p = true;
    if(free_base) free(base);
    res = result.a;
end:
    cu->r = oldr;
    //printf("res=%s\n", res);
    return res;
}

static uint64_t loc_to_offset(struct dwarf_location loc) {
    if(loc.is_constant) {
        return loc.constant;
    } else {
        uint8_t code = read_t(uint8_t, &loc.r);
        if(code == DW_OP_plus_uconst || code == DW_OP_constu)
            return read_uleb128(&loc.r);
        else
            return -1;
    }
}

static void skip_node_children(struct cu_ctx *cu, const struct dwarf_node *node) {
    int depth = node->has_children ? 1 : 0;
    while(depth > 0) {
        struct dwarf_node subnode;
        if(!parse_die(cu, &subnode)) {
            --depth;
        } else {
            if(subnode.has_children)
                ++depth;
        }
    }
}

static bool struct_die_to_json(struct export_ctx *ec, struct cu_ctx *cu, const struct dwarf_node *node, const char *myname) {
    struct tjson *tj = &ec->tj;
    if(!(node->tag == DW_TAG_class_type || node->tag == DW_TAG_structure_type))
        return false;
    if(!(node->flag & (1 << AFL_BYTE_SIZE))) {
        // partial
        return false;
    }

    int putret;
    kh_put(strset, ec->seen, myname, &putret);
    if(putret <= 0) {
        // already seen
        return false;
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
            //struct reader next = cu->r;

            const char *name;
            if(subnode.tag == DW_TAG_inheritance)
                name = "_parent";
            else if(subnode.flag & (1 << AFL_NAME))
                name = subnode.at_name;
            else
                name = "<anon>";

            //printf("?? name=%s tag=%s\n", name, dwarf_tag_name(subnode.tag));

            switch(subnode.tag) {
            case DW_TAG_member:
            case DW_TAG_inheritance: {
                if(!(subnode.flag & (1 << AFL_DATA_MEMBER_LOCATION))) {
                    // static or something
                    break;
                }
                bool free_typename;
                size_t size;
                char *typename = get_full_type_name(cu, ec->name_map, subnode.at_type, &free_typename, &size);

                tjson_dict_start(tj);
                    tjson_dict_key(tj, "name");
                    tjson_str(tj, name);
                    uint64_t offset = loc_to_offset(subnode.at_data_member_location);

                    if(offset != -1) {
                        tjson_dict_key(tj, "offset");
                        tjson_num(tj, offset);
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
                switch_to_dwarf_ref(&cu, NULL, subnode.at_sibling);
            else
                skip_node_children(cu, &subnode);
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
    return true;
}

static void var_die_to_json(struct export_ctx *ec, struct cu_ctx *cu, struct dwarf_node *node, const char *myname) {
    if(node->tag != DW_TAG_variable)
        return;
    if(!(node->flag & (1 << AFL_TYPE)))
        return;
    int putret;
    kh_put(strset, ec->seen, myname, &putret);
    if(putret <= 0)
        return;
    tjson_dict_key(&ec->tj, myname);
    size_t ignsize;
    bool must_free;
    char *type = get_full_type_name(cu, ec->name_map, node->at_type, &must_free, &ignsize);
    tjson_str(&ec->tj, type);
}

static void debug_pubx_cu_to_json(struct cu_ctx *cu, struct export_ctx *ec, bool is_types) {
    struct cu_ctx debug_info_cu;
    uint64_t debug_info_offset = read_fmtbits(cu);
    uint64_t debug_info_size = read_fmtbits(cu);
    struct reader debug_info_r = reader_slice(debug_info, debug_info_offset, debug_info_size);
    parse_cu_header(&debug_info_cu, &debug_info_r);
    parse_debug_info_header(&debug_info_cu);
    struct reader oldr = cu->r;


    if(is_types) {
        // get the qualified names
        while(1) {
            uint64_t die_offset = read_fmtbits(cu);
            if(!die_offset) break;
            struct reader myname = read_cstr(&cu->r);
            int _;
            khiter_t k = kh_put(ccp, ec->name_map, die_offset, &_);
            kh_value(ec->name_map, k) = myname.ptr;
        }

        cu->r = oldr;
    }

    while(1) {
        uint64_t die_offset = read_fmtbits(cu);
        if(!die_offset) break;
        struct reader myname = read_cstr(&cu->r);
        debug_info_cu.r = reader_slice_to_end(debug_info_cu.full_r, die_offset);
        struct dwarf_node node;
        assert(parse_die(&debug_info_cu, &node));
        if(is_types)
            struct_die_to_json(ec, &debug_info_cu, &node, myname.ptr);
        else
            var_die_to_json(ec, &debug_info_cu, &node, myname.ptr);
    }
}

static void debug_pubnames_cu_to_json(struct cu_ctx *cu, void *_ec) {
    debug_pubx_cu_to_json(cu, _ec, false);
}

static void debug_pubtypes_cu_to_json(struct cu_ctx *cu, void *_ec) {
    debug_pubx_cu_to_json(cu, _ec, true);
}

static void debug_info_cu_to_json(struct cu_ctx *restrict cu, void *_ec) {
    // basically, brute force
    struct export_ctx *ec = _ec;
    struct reader oldr = cu->r;
    kvec_t(char) namespace = {0};
    kvec_t(size_t) namespace_lens = {0};

    // pass 0: fill in the names
    // pass 1: print
    for(int pass = 0; pass <= 1; pass++) {
        int depth = 0;
        while(cu->r.ptr != cu->r.end) {
            struct dwarf_node node;
            void *ptr = cu->r.ptr;
            if(!parse_die(cu, &node)) {
                assert(--depth >= 0);
                namespace.n = kv_pop(namespace_lens);
                continue;
            }

            switch(node.tag) {
            case DW_TAG_class_type:
            case DW_TAG_structure_type:
            case DW_TAG_union_type:
            case DW_TAG_enumeration_type:
            case DW_TAG_typedef:
            case DW_TAG_base_type: {
                const char *base = (node.flag & (1 << AFL_NAME)) ? node.at_name : "<?>";
                char *name;
                asprintf(&name, "%.*s%s", (int) namespace.n, namespace.a, base);
                //printf(">> %s\n", name);
                if(pass == 0) {
                    int _;
                    assert(ptr >= debug_info.ptr && ptr < debug_info.end);
                    khiter_t k = kh_put(ccp, ec->name_map, ptr - debug_info.ptr, &_);
                    kh_value(ec->name_map, k) = name;
                } else {
                    struct reader xoldr = cu->r;
                    if(!struct_die_to_json(ec, cu, &node, name))
                        free(name);
                    cu->r = xoldr;
                }
                // fall through
            }
            case DW_TAG_namespace:
                if(node.has_children) {
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

            /*
            // skip children
            if(node.flag & (1 << AFL_SIBLING)) {
                switch_to_dwarf_ref(&cu, &oldr, node.at_sibling);
            } else 
            */
            if(node.has_children) {
                kv_push(size_t, namespace_lens, kv_size(namespace));
                depth++;
            }
        }
        cu->r = oldr;
    }

    ec->name_map_needs_mass_free = true;
    kv_destroy(namespace);
    kv_destroy(namespace_lens);
}

static void debug_info_each_cu_to_json(cu_vec_t *v, struct export_ctx *ec) {
    size_t n = v->n;
    for(size_t i = 0; i < n; i++) {
        if(i % 100 == 0)
            fprintf(stderr, "[%zu/%zu]\n", i, v->n);
        debug_info_cu_to_json(&v->a[i], ec);
    }
}


static void debug_info_cu_dump(struct cu_ctx *restrict cu, void *is_types) {
    parse_debug_info_header(cu);
    if(is_types)
        parse_debug_types_header(cu);
    int depth = 0;
    struct reader *r = &cu->r;
    while(r->ptr != r->end) {
        uint64_t offset = cu->r.ptr - cu->full_r.ptr;
        uint64_t abbrev = read_uleb128(&cu->r);
        if(!abbrev) {
            assert(--depth >= 0);
            continue;
        }
        struct dwarf_abbr *ab;
        if(abbrev >= kv_size(cu->acu->abbrs) ||
           (ab = &kv_A(cu->acu->abbrs, abbrev), !ab->tag))
            panic("bad abbrev 0x%02llx (we probably got misaligned)\n", abbrev);

        for(int i = 0; i < depth; i++) putchar(' ');
        printf("[%llx] %s\n", offset, dwarf_tag_name(ab->tag));
        for(struct dwarf_cached_attr *ca = ab->attrs; ca->form; ca++) {
            for(int i = 0; i < depth; i++) putchar(' ');
            printf("  %s: <%s> ", dwarf_at_name(ca->name), dwarf_form_name(ca->form & ~FORM_DATA_AS_LOCATION));
            char buf[64];
            parse_attr(cu, ca->form, buf);
            switch(ca->form & ~FORM_DATA_AS_LOCATION) {
            case DW_FORM_strp:
            case DW_FORM_string:
                printf("\"%s\"", *(const char **) buf);
                break;
            case DW_FORM_data1:
            case DW_FORM_ref1:
            case DW_FORM_data2:
            case DW_FORM_ref2:
            case DW_FORM_data4:
            case DW_FORM_ref4:
            case DW_FORM_data8:
            case DW_FORM_ref_sig8: // we won't even notice
            case DW_FORM_ref8:
            case DW_FORM_udata:
            case DW_FORM_ref_udata:
            case DW_FORM_sdata:
            case DW_FORM_addr:
            case DW_FORM_secoffset:
                printf("%llx", *(uint64_t *) buf);
                break;
            case DW_FORM_block1:
            case DW_FORM_block2:
            case DW_FORM_block4:
            case DW_FORM_block:
            case DW_FORM_exprloc:
                printf("some data");
                break;
            case DW_FORM_flag:
            case DW_FORM_flag_present:
                printf("%s", *(bool *) buf ? "true" : "false");
                break;
            default:
                assert(0);
            }
            printf("\n");
        }
        if(ab->has_children)
            depth++;
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

        while(1) {
            uint64_t abbrev = read_uleb128(&r);
            if(!abbrev) {
                break;
            }
            uint32_t tag = (uint32_t) read_uleb128(&r);
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

                // we'll need to be able to skip it in any case
                switch(attr_form) {
                case DW_FORM_strp:
                case DW_FORM_string:

                case DW_FORM_ref1:
                case DW_FORM_ref2:
                case DW_FORM_ref4:
                case DW_FORM_ref8:
                case DW_FORM_ref_sig8:
                case DW_FORM_ref_udata:
                case DW_FORM_ref_addr:

                case DW_FORM_data1:
                case DW_FORM_data2:
                case DW_FORM_data4:
                case DW_FORM_data8:
                case DW_FORM_udata:
                case DW_FORM_sdata:
                case DW_FORM_addr:
                case DW_FORM_secoffset:

                case DW_FORM_block1:
                case DW_FORM_block2:
                case DW_FORM_block4:
                case DW_FORM_block:
                case DW_FORM_exprloc:

                case DW_FORM_flag:
                case DW_FORM_flag_present:
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
                    case DW_FORM_ref_sig8:
                    case DW_FORM_ref_udata:
                    case DW_FORM_ref_addr:
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
                    case DW_FORM_secoffset:
                        break;
                    default:
                        goto bad;
                    }
                    break;
                case DW_AT_data_member_location:
                    ca.node_offset = offsetof(struct dwarf_node, at_data_member_location);
                    ab.flag |= 1 << AFL_DATA_MEMBER_LOCATION;
                    goto location;
                case DW_AT_vtable_elem_location:
                    ca.node_offset = offsetof(struct dwarf_node, at_vtable_elem_location);
                    ab.flag |= 1 << AFL_VTABLE_ELEM_LOCATION;
                    goto location;
                location:
                    switch(attr_form) {
                    case DW_FORM_block1:
                    case DW_FORM_block2:
                    case DW_FORM_block4:
                    case DW_FORM_block:
                    case DW_FORM_exprloc:
                        break;
                    // apparently these are ok too
                    case DW_FORM_data1:
                    case DW_FORM_data2:
                    case DW_FORM_data4:
                    case DW_FORM_data8:
                    case DW_FORM_udata:
                    case DW_FORM_sdata:
                        attr_form |= FORM_DATA_AS_LOCATION;
                        break;
                    default:
                        goto bad;
                    }
                    break;

                default:
                    ca.node_offset = 0;
                    break;
                }

                ca.form = attr_form;
                assert(attr_form);

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


static struct reader *get_reader_for_sectname(const char *name, size_t name_size) {
    if(!strncmp(name, "debug_abbrev", name_size))
        return &debug_abbrev;
    else if(!strncmp(name, "debug_info", name_size))
        return &debug_info;
    else if(!strncmp(name, "debug_types", name_size))
        return &debug_types;
    else if(!strncmp(name, "debug_pubtypes", name_size))
        return &debug_pubtypes;
    else if(!strncmp(name, "debug_pubnames", name_size))
        return &debug_pubnames;
    else if(!strncmp(name, "debug_str", name_size))
        return &debug_str;
    else
        return NULL;
}

static void parse_elf(const char *testhdr) {
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
        assert(sizeof(ehdr) <= file_size);
        ehdr *eh = file_map;
        assert(sadd64(eh->e_shoff, smul64(eh->e_shnum, eh->e_shentsize)) <= file_size);
        assert(eh->e_shstrndx <= eh->e_shnum);
        shdr *strsh = (void *) ((char *) file_map + eh->e_shoff + eh->e_shstrndx * eh->e_shentsize);

        for(int i = 0; i < eh->e_shnum; i++) {
            shdr *sh = (void *) ((char *) file_map + eh->e_shoff + i * eh->e_shentsize);
            assert(sh->sh_name < strsh->sh_size);
            uint64_t name_off = sadd64(sh->sh_name, strsh->sh_offset);
            assert(name_off < file_size);
            const char *name = (char *) file_map + name_off;
            size_t name_size = file_size - name_off;
            struct reader *reader = get_reader_for_sectname(name + 1, name_size ? (name_size - 1) : 0);
            if(reader) {
                assert(sadd64(sh->sh_offset, sh->sh_size) <= file_size);
                reader->ptr = (char *) file_map + sh->sh_offset;
                reader->end = reader->ptr + sh->sh_size;
            }
        }
    )
#undef CASES

    default:
        assert(false);
    }
}

static void parse_macho() {
    struct mach_header *mh = file_map;
    struct mach_header_64 *mh64 = file_map;
    struct load_command *load_commands;
    if(mh->magic == MH_MAGIC_64)
        load_commands = (void *) (mh64 + 1);
    else
        load_commands = (void *) (mh + 1);
    struct load_command *lc = load_commands;
    for(uint32_t i = 0; i < mh->ncmds; i++) {
        assert(sadd64((void *) lc - file_map, sizeof(*lc)) <= file_size);
        assert(sadd64((void *) lc - file_map, lc->cmdsize) <= file_size);
        switch(lc->cmd) {
#define CASES(text...) \
    case LC_SEGMENT: { \
        typedef struct segment_command segcmd; \
        typedef struct section sectcmd; \
        text \
        break; \
    } \
    case LC_SEGMENT_64: { \
        typedef struct segment_command_64 segcmd; \
        typedef struct section_64 sectcmd; \
        text \
        break; \
    }
        CASES(
            segcmd *seg = (void *) lc;
            assert(lc->cmdsize >= sizeof(*seg));
            sectcmd *sect = (void *) (seg + 1);
            assert(sadd64(sizeof(*seg), smul64(seg->nsects, sizeof(*sect))) <= lc->cmdsize);
            for(uint32_t i = 0; i < seg->nsects; i++, sect++) {
                const char *name = sect->sectname;
                if(!(name[0] == '_' && name[1] == '_'))
                    continue;
                struct reader *reader = get_reader_for_sectname(name + 2, 14);
                if(reader) {
                    assert(sadd64(sect->offset, sect->size) <= file_size);
                    reader->ptr = file_map + sect->offset;
                    reader->end = reader->ptr + sect->size;
                }
            }
        )
        default:
            break;
        }

        lc = (void *) lc + lc->cmdsize;
    }
}

int main(int argc, char **argv) {
    set_block_buffered(stdout);

    int fd = open(argv[1], O_RDONLY);
    assert(fd != -1);
    off_t off = lseek(fd, 0, SEEK_END);
    file_size = off;
    assert(off == file_size);
    file_map = mmap(NULL, file_size, PROT_READ, MAP_SHARED, fd, 0);
    assert(file_map != MAP_FAILED);

    assert(file_size >= 5);
    const char *testhdr = file_map;
    if(!memcmp(testhdr, ELFMAG, 4)) {
        parse_elf(testhdr);
    } else if(*(uint32_t *) testhdr == MH_MAGIC || *(uint32_t *) testhdr == MH_MAGIC_64) { // not bothering with swapping for now
        parse_macho();
    } else {
        assert(!"Unknown file type");
    }

    assert(debug_abbrev.ptr);
    parse_debug_abbrev(debug_abbrev);

    if(0) {
        if(debug_info.ptr) {
            printf(".debug_info:\n");
            parse_all_cus(debug_info, debug_info_cu_dump, (void *) 0);
        }
        if(debug_types.ptr) {
            printf(".debug_types:\n");
            parse_all_cus(debug_types, debug_info_cu_dump, (void *) 1);
        }
        return 0;
    }

    init_info_cu_vec(debug_info, &debug_info_cus);
    //init_types_cu_vec(debug_types, &debug_types_cus);

    struct export_ctx ec;
    export_ctx_init(&ec, debug_info.end - debug_info.ptr);
    tjson_dict_start(&ec.tj);
    if(debug_pubtypes.ptr && 0) {
        parse_all_cus(debug_pubtypes, debug_pubtypes_cu_to_json, &ec);
    } else {
        debug_info_each_cu_to_json(&debug_info_cus, &ec);
    }
    if(1 && debug_pubnames.ptr) { // xxx
        tjson_dict_key(&ec.tj, ".globals");
        tjson_dict_start(&ec.tj);
        parse_all_cus(debug_pubnames, debug_pubnames_cu_to_json, &ec);
        tjson_dict_end(&ec.tj);
    }
    tjson_dict_end(&ec.tj);
    putchar('\n');
    export_ctx_destroy(&ec);
}
