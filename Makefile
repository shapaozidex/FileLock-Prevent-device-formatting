
ifndef KP_DIR
    KP_DIR = ./KernelPatch
endif

TOOLCHAIN_PATH ?= /home/arm-gnu-toolchain-13.3.rel1-x86_64-aarch64-none-elf/bin
CC = $(TOOLCHAIN_PATH)/aarch64-none-elf-gcc
LD = $(TOOLCHAIN_PATH)/aarch64-none-elf-ld

# 修改包含目录以匹配头文件需求
INCLUDE_DIRS := . \
                include \
                patch/include \
                linux/include \
                kpm/include \
                linux/arch/arm64/include \
                linux/tools/arch/arm64/include \
				
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir)) -I./src

# c文件添加在这里
BASE_SRCS += ./src/main.c
BASE_SRCS += ./src/module.c

SRCS += $(BASE_SRCS)

OBJS := $(SRCS:.c=.o)
OBJS := $(OBJS:.S=.o)

all: module.kpm

module.kpm: ${OBJS}
	${CC} -r -o $@ $^
	find . -name "*.o" | xargs rm -f

%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -c -O2 -o $@ $<

.PHONY: clean
clean:
	rm -rf *.kpm
	find . -name "*.o" | xargs rm -f