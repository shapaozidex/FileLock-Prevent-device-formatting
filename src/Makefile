KP_DIR = ../__KernelPatch_lib

CC = aarch64-none-elf-gcc
LD = aarch64-none-elf-ld

INCLUDE_DIRS := . include patch/include linux/include kpm/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

# 使用 wildcard 函数获取当前目录下的所有 .c 文件
C_FILES := $(wildcard *.c)

# 将 .c 文件转换为 .o 文件
OBJS := $(C_FILES:.c=.o)

CFLAGS := -g -fno-pie -fno-stack-protector -fno-omit-frame-pointer -fno-common
LDFLAGS := -r

all: mod_main.kpm

mod_main.kpm: $(OBJS)
	${CC} $(LDFLAGS) -o $@ $^

# 添加编译规则
%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -c -O2 -o $@ $<

.PHONY: clean
clean:
	rm -rf *.kpm
	find . -name "*.o" | xargs rm -f