#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <time.h>
#include <unistd.h>
#include "monitor_common.h"

static pid_t find_pid(const char* name)
{
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0};
    pid_t mypid = getpid();
    pid_t pid = -1;
    size_t buf_size = 0;
    uint8_t* buf = NULL;

    if(sysctl(mib, 4, NULL, &buf_size, NULL, 0))
        return -1;

    buf = malloc(buf_size);
    if(!buf)
        return -1;

    if(sysctl(mib, 4, buf, &buf_size, NULL, 0))
    {
        free(buf);
        return -1;
    }

    for(uint8_t* ptr = buf; ptr < buf + buf_size;)
    {
        int ki_structsize = *(int*)ptr;
        pid_t ki_pid = *(pid_t*)&ptr[72];
        char* ki_tdname = (char*)&ptr[447];

        ptr += ki_structsize;
        if(ki_pid == mypid)
            continue;
        if(strcmp(ki_tdname, name) == 0)
            pid = ki_pid;
    }

    free(buf);
    return pid;
}

static int wait_for_exit(pid_t pid)
{
    struct timespec sleep_time = {.tv_sec = 0, .tv_nsec = 100000000L};

    for(int i = 0; i < 100; i++)
    {
        if(kill(pid, 0) && errno == ESRCH)
            return 0;
        nanosleep(&sleep_time, NULL);
    }

    return -1;
}

int main(void)
{
    pid_t pid;
    int stopped = 0;

    while((pid = find_pid(PATHLOG_MONITOR_PROC_NAME)) > 0)
    {
        if(kill(pid, SIGTERM))
        {
            perror("kill");
            return 1;
        }

        if(wait_for_exit(pid))
        {
            fprintf(stderr, "pathlog monitor did not exit cleanly (pid %d)\n", pid);
            return 1;
        }

        stopped = 1;
        sleep(1);
    }

    if(!stopped)
    {
        printf("pathlog monitor is not running\n");
        return 0;
    }

    printf("pathlog monitor stopped\n");
    return 0;
}
