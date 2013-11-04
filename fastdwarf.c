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
#include "elf.h"

static void *debug_abbrev;
static size_t debug_abbrev_size;

static struct abbrev_cache_entry {
    uint64_t offset;
    char *opcodes;
} cache_entries[256];

typedef struct {
    void *ptr;
    void *end;
} die_t;

static void 

static void parse_debug_info(

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

    void *debug_info, *debug_types;
    size_t debug_info_size, debug_types_size;

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
            void **ptrp; size_t *sizep;
            if(!strncmp(name, ".debug_abbrev", name_size)) {
                ptrp = &debug_abbrev; sizep = &debug_abbrev_size;
            } else if(!strncmp(name, ".debug_info", name_size)) {
                ptrp = &debug_info; sizep = &debug_info_size;
            } else if(!strncmp(name, ".debug_types", name_size)) {
                ptrp = &debug_types; sizep = &debug_types_size;
            } else {
                continue;
            }
            assert(sadd64(sh->sh_offset, sh->sh_size) <= size);
            *ptrp = (char *) file_map + sh->sh_offset;
            *sizep = sh->sh_size;
        }
    )

    default:
        assert(false);
    }

    assert(debug_abbrev);
    parse_debug_abbrev(debug_abbrev, debug_abbrev);
    if(debug_info) {
        parse_debug_info(debug_info, debug_info_size);
    }
    if(debug_types) {
        parse_debug_info(debug_types, debug_types_size);
    }
}
