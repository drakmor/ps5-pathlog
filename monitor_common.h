#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define PATHLOG_MONITOR_PROC_NAME "pathlog.elf"
#define PATHLOG_LOG_DIR "/data/pathlog"
#define PATHLOG_ALL_LOG_PATH PATHLOG_LOG_DIR "/all.log"
#define PATHLOG_POLL_NSEC 10000000L

typedef struct notify_request {
    char unused[45];
    char message[3075];
} notify_request_t;

typedef struct app_info {
    uint32_t app_id;
    uint64_t unknown1;
    char title_id[14];
    char unknown2[0x3c];
} app_info_t;

int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);
int sceKernelGetAppInfo(pid_t pid, app_info_t* info);
