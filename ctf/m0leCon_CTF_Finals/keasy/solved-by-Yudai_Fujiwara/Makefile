all:
#	python gen.py
	musl-gcc exploit.c -o pwn -static
#	gcc exploit.c -o pwn -static
#	gcc -S exploit.c -o exploit.S
#	musl-gcc exploit.S -o pwn -static -lkeyutils
	mv pwn mount/root/bin
	cd mount/root; find . -print0 | cpio -o --null --format=newc --owner=root > ../debugfs.cpio
	cd mount; gzip debugfs.cpio
	mv mount/debugfs.cpio.gz rootfs.cpio.gz
	./run.sh
