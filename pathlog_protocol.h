#pragma once

#include <stddef.h>
#include <stdint.h>

enum
{
    UELF_PATH_LOG_ENTRY_COUNT = 50,
    UELF_PATH_LOG_PATH_MAX = 240,
};

enum
{
    UELF_PATH_LOG_KIND_OPEN = 1,
    UELF_PATH_LOG_KIND_OPENAT = 2,
    UELF_PATH_LOG_KIND_STAT = 3,
    UELF_PATH_LOG_KIND_LSTAT = 4,
    UELF_PATH_LOG_KIND_NSTAT = 5,
    UELF_PATH_LOG_KIND_FSTATAT = 6,
};

struct uelf_path_log_entry
{
    uint64_t seq;
    uint16_t kind;
    uint16_t length;
    char path[UELF_PATH_LOG_PATH_MAX];
};

struct uelf_path_log_snapshot
{
    uint64_t write_seq;
    uint32_t entry_count;
    uint32_t logging_enabled;
    uint32_t filter_length;
    char filter[UELF_PATH_LOG_PATH_MAX];
    struct uelf_path_log_entry entries[UELF_PATH_LOG_ENTRY_COUNT];
};

_Static_assert(sizeof(struct uelf_path_log_entry) == 256, "Unexpected pathlog entry ABI size");
_Static_assert(offsetof(struct uelf_path_log_snapshot, entries) == 264, "Unexpected pathlog snapshot header ABI");
_Static_assert(sizeof(struct uelf_path_log_snapshot) == 13064, "Unexpected pathlog snapshot ABI size");
