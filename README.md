# KernelMod
A linux(android) kernel module that prevents important files from being deleted

这是学习linux内核时顺便写的，使用了kernelpatch提供的api

通过hook do_unlinkat 和 do_rmdir函数实现拦截删除操作，从而避免文件被删除

还有一些不足，但是以后也不会改了，感兴趣的可以自行修改
