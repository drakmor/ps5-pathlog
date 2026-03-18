PS5_HOST ?= ps5
PS5_PORT ?= 9021
PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk
TMPDIR ?= $(CURDIR)/.tmp
export TMPDIR

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

MONITOR_ALL_ELF := pathlog_all.elf
MONITOR_APPS_ELF := pathlog_apps.elf
STOP_ELF := pathlog_stop.elf
ELFS := $(MONITOR_ALL_ELF) $(MONITOR_APPS_ELF) $(STOP_ELF)
LEGACY_ELFS := pathlog_payload.elf

CFLAGS := -Wall -Werror -g -rdynamic

all: $(ELFS)

$(MONITOR_ALL_ELF): main.c monitor_common.h pathlog_protocol.h | $(TMPDIR)
	$(CC) $(CFLAGS) -DPATHLOG_MONITOR_MODE_ALL=1 -o $@ main.c

$(MONITOR_APPS_ELF): main.c monitor_common.h pathlog_protocol.h | $(TMPDIR)
	$(CC) $(CFLAGS) -DPATHLOG_MONITOR_MODE_APPS=1 -o $@ main.c

$(STOP_ELF): stop.c monitor_common.h | $(TMPDIR)
	$(CC) $(CFLAGS) -o $@ stop.c

$(TMPDIR):
	mkdir -p $@

clean:
	rm -f $(ELFS) $(LEGACY_ELFS)
	rm -rf $(TMPDIR)

test: $(ELFS)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $(ELFS)
