cmake_minimum_required(VERSION 3.25.2)
project(sys_security C)

set(CMAKE_C_STANDARD 99)

set(KP_DIR "$KernelPatch")
set(INCLUDE_DIRS . include patch/include linux/include kpm/include linux/arch/arm64/include linux/tools/arch/arm64/include)

foreach(dir ${INCLUDE_DIRS})
    include_directories(${KP_DIR}/kernel/${dir})
endforeach()

set(OUTPUT_NAME "yuuki")

set(CMAKE_C_COMPILER /opt/android-ndk-r27/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang)

set(SOURCES mod_main.c
        data_parse.h
        data_parse.c
)

add_library(${OUTPUT_NAME} SHARED ${SOURCES})

set_target_properties(${OUTPUT_NAME} PROPERTIES OUTPUT_NAME "${OUTPUT_NAME}")

add_custom_command(TARGET ${OUTPUT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E rename $<TARGET_FILE:${OUTPUT_NAME}> ${CMAKE_CURRENT_BINARY_DIR}/${OUTPUT_NAME}.kpm
)