#!/bin/bash

# 构建项目
echo "Building the project..."
make

# 检查 make 是否成功
if [ $? -ne 0 ]; then
    echo "Build failed. Exiting."
    exit 1
fi

# 将 mod_main.kpm 推送到设备
echo "Pushing mod_main.kpm to device..."
adb push mod_main.kpm /data/local/tmp

# 检查 adb push 是否成功
if [ $? -ne 0 ]; then
    echo "Failed to push mod_main.kpm to device. Exiting."
    exit 1
fi

# 以 root 权限加载 kpatch 模块
echo "Loading kpatch module with root permission..."
adb shell "su -c 'kpatch 107017li kpm load /data/local/tmp/mod_main.kpm'"

# 检查 kpatch 是否成功
if [ $? -ne 0 ]; then
    echo "Failed to load kpatch module. Exiting."
    exit 1
fi

# 清理生成的 .o 文件和 .kpm 文件
echo "Cleaning up generated files..."
make clean

echo "Build and deployment completed successfully."