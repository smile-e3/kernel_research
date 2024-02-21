# Linux内核相关API

> Linux API文档：https://docs.kernel.org/index.html#/

1.[anon_inode_getfile](https://docs.kernel.org/filesystems/api-summary.html?highlight=anon_inode_getfile#/c.anon_inode_getfile)
> 功能描述：负责创建一个匿名inode并将其与一个文件结构关联起来。这个函数主要用于在内核中创建没有对应磁盘文件的文件对象。

2.[get_unused_fd_flags]()
> 功能描述：获取一样未使用的fd