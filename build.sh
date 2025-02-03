#!/bin/bash


# 清理函数
make clean

# 在脚本退出时自动清理
trap cleanup EXIT

echo "Building the project..."

# 执行make
make

if [ ${PIPESTATUS[0]} -ne 0 ]; then
    echo "Build failed. Exiting."
    exit 1
fi

echo "Pushing module.kpm to device..."
adb push module.kpm /storage/emulated/0/Download/

if [ $? -ne 0 ]; then
    echo "Failed to push module.kpm to device. Exiting."
    exit 1
fi



