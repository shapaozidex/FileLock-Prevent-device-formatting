#!/bin/bash

echo "Building the project..."
make

if [ $? -ne 0 ]; then
    echo "Build failed. Exiting."
    exit 1
fi

echo "Pushing mod_main.kpm to device..."
adb push mod_main.kpm /data/local/tmp

if [ $? -ne 0 ]; then
    echo "Failed to push mod_main.kpm to device. Exiting."
    exit 1
fi

echo "Loading kpatch module with root permission..."
adb shell "su -c 'kpatch 107017li kpm load /data/local/tmp/mod_main.kpm'"

# 检查 kpatch 是否成功
if [ $? -ne 0 ]; then
    echo "Failed to load kpatch module. Exiting."
    exit 1
fi

echo "Cleaning up generated files..."
make clean

echo "Build and deployment completed successfully."