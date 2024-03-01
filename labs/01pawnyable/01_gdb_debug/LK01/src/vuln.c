#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

// 模块的协议
MODULE_LICENSE("GPL");

// 模块的作者
MODULE_AUTHOR("ptr-yudai");

// 模块的描述
MODULE_DESCRIPTION("Holstein v1 - Vulnerable Kernel Driver for Pawnyable");

// 定义DEVICE设备名称
#define DEVICE_NAME "holstein"

// 定义缓冲区大小
#define BUFFER_SIZE 0x400

// 定义一个全局的buf指针
char *g_buf = NULL;

static int module_open(struct inode *inode, struct file *file)
{
  printk(KERN_INFO "module_open called\n");

  // 使用内核内存分配函数kmalloc分配大小(0x400)
  g_buf = kmalloc(BUFFER_SIZE, GFP_KERNEL);
  if (!g_buf) {
    printk(KERN_INFO "kmalloc failed");
    return -ENOMEM;
  }

  return 0;
}

static ssize_t module_read(struct file *file,
                        char __user *buf, size_t count,
                        loff_t *f_pos)
{
  char kbuf[BUFFER_SIZE] = { 0 };

  printk(KERN_INFO "module_read called\n");

  memcpy(kbuf, g_buf, BUFFER_SIZE);
  if (_copy_to_user(buf, kbuf, count)) {
    printk(KERN_INFO "copy_to_user failed\n");
    return -EINVAL;
  }

  return count;
}

static ssize_t module_write(struct file *file,
                            const char __user *buf, size_t count,
                            loff_t *f_pos)
{
  char kbuf[BUFFER_SIZE] = { 0 };

  printk(KERN_INFO "module_write called\n");

  // vul1:栈溢出漏洞
  if (_copy_from_user(kbuf, buf, count)) {
    printk(KERN_INFO "copy_from_user failed\n");
    return -EINVAL;
  }
  memcpy(g_buf, kbuf, BUFFER_SIZE);

  return count;
}

static int module_close(struct inode *inode, struct file *file)
{
  printk(KERN_INFO "module_close called\n");
  kfree(g_buf);
  return 0;
}

// 该模块只定义了四个进程：open、read、write、close，其他的没有实现（调用时什么也没有发生）
// THIS_MODULE 是一个宏，用于在 Linux 内核中指向当前模块的 struct module 结构体的指针。
// 在文件操作结构体的 .owner 字段中，将 .owner 设置为 THIS_MODULE 的目的是将该文件操作结构体
// 与当前模块进行关联。
static struct file_operations module_fops =
  {
   .owner   = THIS_MODULE,
   // 通过文件类型的结构体，使得程序包含了文件的特性函数如读、写、打开、关闭
   .read    = module_read,
   .write   = module_write,
   .open    = module_open,
   .release = module_close,
  };

static dev_t dev_id;

// 定义结构体，cdev_init()函数将dev权限进行存储
/*
在 Linux 内核开发中，cdev 是一个重要的结构体，用于表示字符设备（character device）的相关信息和操作。它包含了与字符设备相关的函数指针和数据。

下面是 cdev 结构体的定义：
struct cdev {
    struct kobject kobj;       // 内核对象
    struct module *owner;      // 拥有该字符设备的模块指针
    struct file_operations *ops;    // 文件操作函数指针
    struct list_head list;     // 链表节点，用于将多个字符设备连接起来
    dev_t dev;                 // 字符设备的设备号
    unsigned int count;        // 字符设备的使用计数
};
cdev 结构体的成员包括：
kobj：一个 kobject 结构体成员，表示内核对象，用于管理字符设备的相关信息。
owner：一个指向拥有该字符设备的模块的指针。它用于在模块加载和卸载期间对模块进行引用计数，确保在使用该字符设备时模块不会被卸载。
ops：一个指向 file_operations 结构体的指针，表示与字符设备相关的文件操作函数。通过该指针，可以定义字符设备的打开、读取、写入、关闭等操作的行为。
list：一个 list_head 结构体成员，用于将多个字符设备连接起来，形成一个链表结构。
dev：一个 dev_t 类型的变量，表示字符设备的设备号。设备号用于唯一标识字符设备。
count：一个无符号整数，表示字符设备的使用计数。当字符设备被打开时，计数会增加，关闭时计数会减少。在计数为零时，字符设备可以被卸载或释放。
cdev 结构体提供了一种在内核中管理字符设备的方式。通过初始化和操作 cdev 结构体，可以注册字符设备并定义其行为。
*/
static struct cdev c_dev;

// 模块初始化函数
static int __init module_initialize(void)
{
  // 设备注册
  if (alloc_chrdev_region(&dev_id, 0, 1, DEVICE_NAME)) {
    printk(KERN_WARNING "Failed to register device\n");
    return -EBUSY;
  }

  // 用于device设备的初始化使用
  /*
  在 Linux 内核开发中，cdev_init() 函数是用于初始化字符设备的 cdev 结构体的函数。它的定义如下：
  void cdev_init(struct cdev *cdev, const struct file_operations *fops);

  cdev_init() 函数接受两个参数：
  cdev：指向要初始化的 cdev 结构体的指针。
  fops：指向字符设备的 file_operations 结构体的指针，即与字符设备相关的文件操作函数。
  */
  cdev_init(&c_dev, &module_fops);
  c_dev.owner = THIS_MODULE;

  if (cdev_add(&c_dev, dev_id, 1)) {
    // 使用dmesg打印内核的信息
    printk(KERN_WARNING "Failed to add cdev\n");

    // device设备取消注册减一
    unregister_chrdev_region(dev_id, 1);
    return -EBUSY;
  }

  return 0;
}

static void __exit module_cleanup(void)
{
  cdev_del(&c_dev);
  unregister_chrdev_region(dev_id, 1);
}

// 模块优先执行初始化操作
module_init(module_initialize);

// 模块最后退出操作
module_exit(module_cleanup);
