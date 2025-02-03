cmake_minimum_required(VERSION 3.10)
project(kernel_module C)

# 设置默认的 KP_DIR 依赖路径
if(NOT DEFINED KP_DIR)
    set(KP_DIR "./KernelPatch")
endif()

# 设置工具链路径
set(TOOLCHAIN_PATH "/home/arm-gnu-toolchain-13.3.rel1-x86_64-aarch64-none-elf/bin" CACHE PATH "Path to the toolchain")
set(CMAKE_C_COMPILER "${TOOLCHAIN_PATH}/aarch64-none-elf-gcc")
set(CMAKE_LINKER "${TOOLCHAIN_PATH}/aarch64-none-elf-ld")

# 设置编译选项
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")

# 添加依赖目录
set(KERNEL_INCLUDE_DIRS
    ${KP_DIR}/kernel/include
    ${KP_DIR}/kernel/patch/include
    ${KP_DIR}/kernel/linux/include
    ${KP_DIR}/kernel/kpm/include
    ${KP_DIR}/kernel/linux/arch/arm64/include
    ${KP_DIR}/kernel/linux/tools/arch/arm64/include
)

include_directories(
    ${KERNEL_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/src
)

# 添加源文件
set(SOURCE_FILES
    ./src/main.c
    ./src/module.c
)


# 创建目标
add_library(module SHARED ${SOURCE_FILES})
set_target_properties(module PROPERTIES
    OUTPUT_NAME "module"
    SUFFIX ".kpm"
    POSITION_INDEPENDENT_CODE ON
)

# 安装规则（可选）
install(TARGETS module
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
) 