#!/bin/bash

# 安装环境

sudo apt install qemu-system -y

# 安装GDB的插件:GEF
wget -O ~/.gdbinit-gef.py -q https://gef.blah.cat/py
echo source ~/.gdbinit-gef.py >> ~/.gdbinit