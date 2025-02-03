#include <hook.h>
#include <compiler.h>
#include <linux/printk.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/string.h>
#include "file.h"
#include <syscall.h>
#include <linux/errno.h>  // 添加这行来定义 EACCES

// 开关控制变量
static bool enable_do_unlinkat = true;
static bool enable_do_rmdir = true;
static bool enable_do_renameat2 = true;
static bool enable_do_filp_open = true;
// 函数指针
void *do_unlinkat = 0;
void *do_rmdir = 0;
void *do_renameat2 = 0;
void *do_filp_open = 0;
// 静态数组
#define MAX_PROTECTED_PATHS 4000 // 最大保护路径数量
#define MAX_PATH_LENGTH 512     // 每个路径的最大长度

static char protected_directories[MAX_PROTECTED_PATHS][MAX_PATH_LENGTH];
static int path_count = 0;  // 当前路径数量

// 添加新路径
static bool add_protected_path(const char* path) {
    if (path_count >= MAX_PROTECTED_PATHS) {
        pr_info("[yuuki&shapaozidex]: 无法添加更多路径，已达到最大限制\n");
        return false;
    }
    
    if (strlen(path) >= MAX_PATH_LENGTH) {
        pr_info("[yuuki&shapaozidex]: 路径太长: %s\n", path);
        return false;
    }
    
    // 检查路径是否已存在
    for (int i = 0; i < path_count; i++) {
        if (strcmp(protected_directories[i], path) == 0) {
            pr_info("[yuuki&shapaozidex]: 路径已存在: %s\n", path);
            return false;
        }
    }
    
    // 添加新路径
    strncpy(protected_directories[path_count], path, MAX_PATH_LENGTH - 1);
    protected_directories[path_count][MAX_PATH_LENGTH - 1] = '\0';
    path_count++;
    
    pr_info("[yuuki&shapaozidex]: 已添加保护路径: %s\n", path);
    return true;
}

// 移除指定路径
static bool remove_protected_path(const char* path) {
    for (int i = 0; i < path_count; i++) {
        if (strcmp(protected_directories[i], path) == 0) {
            // 移动后面的路径前移
            for (int j = i; j < path_count - 1; j++) {
                strncpy(protected_directories[j], protected_directories[j + 1], MAX_PATH_LENGTH);
            }
            path_count--;
            pr_info("[yuuki&shapaozidex]: 已移除保护路径: %s\n", path);
            return true;
        }
    }
    
    pr_info("[yuuki&shapaozidex]: 未找到要移除的路径: %s\n", path);
    return false;
}

// 删除文件拦截
static void do_unlinkat_before(hook_fargs1_t* args, void* udata) {
    struct filename* pathname = (struct filename*)args->arg1;
    char path_buf[MAX_PROTECTED_PATHS];

    // 默认放行
    args->skip_origin = false;
    args->ret = 0;

    // 更严格的路径检查
    if (!pathname || IS_ERR(pathname) || !pathname->name) {
        return;
    }

    // 初始化缓冲区
    memset(path_buf, 0, MAX_PROTECTED_PATHS);
    strncpy(path_buf, pathname->name, MAX_PROTECTED_PATHS - 1);

    // 检查是否在受保护目录列表中
    for (int i = 0; i < path_count; i++) {
        if (strstr(path_buf, protected_directories[i]) != NULL) {
            pr_info("[yuuki&shapaozidex] do_unlinkat_before: 拦截删除文件操作: %s\n", path_buf);
            args->skip_origin = true;
            args->ret = -EACCES;
            return;
        }
    }

    // 如果没有匹配任何规则，保持默认的跳过行为
    return;
}

// 删除路径拦截
static void do_rmdir_before(hook_fargs2_t *args, void *udata)
{
    struct filename* pathname = (struct filename*)args->arg1;
    char path_buf[MAX_PROTECTED_PATHS];

    // 默认放行
    args->skip_origin = false;
    args->ret = 0;

    // 更严格的路径检查
    if (!pathname || IS_ERR(pathname) || !pathname->name) {
        return;
    }

    // 初始化缓冲区
    memset(path_buf, 0, MAX_PROTECTED_PATHS);
    strncpy(path_buf, pathname->name, MAX_PROTECTED_PATHS - 1);

    // 检查是否在受保护目录列表中
    for (int i = 0; i < path_count; i++) {
        if (strstr(path_buf, protected_directories[i]) != NULL) {
            pr_info("[yuuki&shapaozidex] do_rmdir_before: 拦截删除目录操作: %s\n", path_buf);
            args->skip_origin = true;
            args->ret = -EACCES;
            return;
        }
    }

    // 如果没有匹配任何规则，保持默认的跳过行为
    return;
}

// 重命名拦截
static void do_renameat2_before(hook_fargs3_t* args, void* udata) {
    struct filename* oldname = (struct filename*)args->arg1;
    struct filename* newname = (struct filename*)args->arg3;
    char old_path[MAX_PROTECTED_PATHS];
    char new_path[MAX_PROTECTED_PATHS];

    // 默认放行
    args->skip_origin = false;
    args->ret = 0;

    // 检查路径有效性
    if (!oldname || IS_ERR(oldname) || !oldname->name ||
        !newname || IS_ERR(newname) || !newname->name) {
        return;
    }

    // 获取源路径和目标路径
    memset(old_path, 0, MAX_PROTECTED_PATHS);
    memset(new_path, 0, MAX_PROTECTED_PATHS);
    strncpy(old_path, oldname->name, MAX_PROTECTED_PATHS - 1);
    strncpy(new_path, newname->name, MAX_PROTECTED_PATHS - 1);

    // 检查是否在受保护目录列表中
    for (int i = 0; i < path_count; i++) {
        if (strstr(old_path, protected_directories[i]) != NULL || 
            strstr(new_path, protected_directories[i]) != NULL) {
            pr_info("[yuuki&shapaozidex] do_renameat2_before: 拦截重命名操作: %s -> %s\n", old_path, new_path);
            args->skip_origin = true;
            args->ret = -EACCES;
            return;
        }
    }

    // 如果没有匹配任何规则，保持默认的跳过行为
    return;
}

// 文件操作拦截
static void do_filp_open_before(hook_fargs4_t *args, void *udata)
{
    struct filename *pathname = (struct filename *)args->arg1;
    const struct open_flags *op = (const struct open_flags *)args->arg2;
    char path_buf[MAX_PROTECTED_PATHS];

    // 默认跳过
    args->skip_origin = false;
    args->ret = 0;

    // 更严格的径检查
    if (!pathname || IS_ERR(pathname) || !pathname->name)
    {
        return;
    }

    // 初始化缓冲区
    memset(path_buf, 0, MAX_PROTECTED_PATHS);
    strncpy(path_buf, pathname->name, MAX_PROTECTED_PATHS - 1);

    // 对其他路径，只在写入和创建时进行保护
    if (!(op->open_flag & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)))
    {
        return;
    }

    // 检查是否在受保护目录列表中
    for (int i = 0; i < path_count; i++)
    {
        if (strstr(path_buf, protected_directories[i]) != NULL)
        {
            pr_info("[yuuki&shapaozidex] do_filp_open_before: 拦截文件操作: %s\n", path_buf);
            args->skip_origin = true;
            args->ret = -EACCES;
            return;
        }
    }

    // 如果没有匹配任何规则，保持默认的跳过行为
    return;
}

void hook_init() {
    // 初始化保护路径数组
    memset(protected_directories, 0, sizeof(protected_directories));
    path_count = 0;

    // 获取函数地址
    do_unlinkat = (void *)kallsyms_lookup_name("do_unlinkat");
    do_rmdir = (void *)kallsyms_lookup_name("do_rmdir");
    do_renameat2 = (void *)kallsyms_lookup_name("do_renameat2");
    do_filp_open = (void *)kallsyms_lookup_name("do_filp_open");

    // 安装 hook
    if (do_unlinkat) hook_wrap1(do_unlinkat, do_unlinkat_before, NULL, NULL);
    if (do_rmdir) hook_wrap2(do_rmdir, do_rmdir_before, NULL, NULL);
    if (do_renameat2) hook_wrap3(do_renameat2, do_renameat2_before, NULL, NULL);
    if (do_filp_open) hook_wrap4(do_filp_open, do_filp_open_before, NULL, NULL);
    // 打印 hook 状态，同时考虑函数是否存在
    pr_info("[yuuki&shapaozidex]: do_rmdir : %px (enabled: %s)", do_rmdir, (do_rmdir && enable_do_rmdir) ? "yes" : "no");
    pr_info("[yuuki&shapaozidex]: do_unlinkat : %px (enabled: %s)", do_unlinkat, (do_unlinkat && enable_do_unlinkat) ? "yes" : "no");
    pr_info("[yuuki&shapaozidex]: do_renameat2 : %px (enabled: %s)", do_renameat2, (do_renameat2 && enable_do_renameat2) ? "yes" : "no");
    pr_info("[yuuki&shapaozidex]: do_filp_open : %px (enabled: %s)", do_filp_open, (do_filp_open && enable_do_filp_open) ? "yes" : "no");
            
    pr_info("[yuuki&shapaozidex]: hook 安装完成\n");
}

void hook_deinit(){
    // 只清理需要的hook
    if (do_unlinkat && enable_do_unlinkat) {
        unhook(do_unlinkat);
    }

    if (do_rmdir && enable_do_rmdir) {
        unhook(do_rmdir);
    }

    if (do_renameat2 && enable_do_renameat2) {
        unhook(do_renameat2);
    }

    if (do_filp_open && enable_do_filp_open) {
        unhook(do_filp_open);
    }

    // 清空保护路径数组
    memset(protected_directories, 0, sizeof(protected_directories));
    path_count = 0;
    
    pr_info("[yuuki&shapaozidex]: hook 已移除，保护路径已清空\n");
}

// 控制函数
void hook_control0(const char* data) {
    if (!data) {
        pr_info("[yuuki&shapaozidex]: hook_control0 收到空数据\n");
        return;
    }

    pr_info("[yuuki&shapaozidex]: hook_control0 收到数据: %s\n", data);
    
    if (strncmp(data, "add ", 4) == 0) {
        // 添加新路径
        add_protected_path(data + 4);  // 跳过"add "前缀
    }
    else if (strncmp(data, "remove ", 7) == 0) {
        // 移除路径
        remove_protected_path(data + 7);  // 跳过"remove "前缀
    }
    else if (strcmp(data, "ls") == 0) {
        // 列出所有保护的路径
        pr_info("[yuuki&shapaozidex]: 当前保护的路径列表 (总数: %d):\n", path_count);
        for (int i = 0; i < path_count; i++) {
            pr_info("[yuuki&shapaozidex]: %d: %s\n", i + 1, protected_directories[i]);
        }
    }
}

