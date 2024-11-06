#!/bin/bash

while true
do
    adb shell "su -c 'dmesg -w | grep yuuki'"
    echo
    read -p "Press [Enter] key to continue..."
done