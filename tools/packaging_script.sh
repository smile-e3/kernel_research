#!/bin/bash

# 检查参数数量
if [ $# -ne 3 ]; then
  echo "Usage: $0 <original_cpio.gz> <new_cpio.gz> <file_to_pack>"
  exit 1
fi

# 解包原.cpio.gz文件
echo "Extracting original cpio.gz..."
mkdir original_extracted
cd original_extracted
if [[ "$1" == *.gz ]]; then
  gunzip -c "$1" | cpio -idmv
  cd ..
else
  cpio -idmv < "$1"
  cd ..
fi

# 将新文件复制到解包后的目录中
echo "Copying new file to extracted directory..."
cp "$3" original_extracted/bin

read pause

# 重新打包为新的.cpio.gz文件
echo "Repacking to new cpio.gz file..."
cd original_extracted
# find . -print0 | cpio --null -ov --format=newc | gzip > "$2"
find . -print0 | cpio -o --format=newc --null --owner=root | gzip > "$2"
cd ..

# 清理临时文件和目录
echo "Cleaning up..."
rm -rf original_extracted

echo "Packaging complete!"
