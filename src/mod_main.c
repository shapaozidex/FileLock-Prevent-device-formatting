#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/kern_levels.h>
#include <kpmalloc.h>
#include <asm/current.h>
#include "file.h"
#include "data_parse.h"

KPM_NAME("File_Guard");
KPM_VERSION("1.0.0");
KPM_AUTHOR("yuuki");
KPM_DESCRIPTION("Prevent your phone from being maliciously formatted");

typedef struct file *(*do_filp_open_func_t)(int dfd, struct filename *pathname, const struct open_flags *op);
static do_filp_open_func_t original_do_filp_open = NULL;
static do_filp_open_func_t backup_do_filp_open = NULL;
static struct file *replace_do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op);

static hook_err_t hook_err = HOOK_NOT_HOOK;

static int (*do_unlinkat)(int dfd, struct filename *name);
static int (*do_rmdir)(int dfd, struct filename *name);
static int (*vfs_rename)(struct renamedata *rd);

int (*kern_path)(const char *name, unsigned int flags, struct path *path) = NULL;
char *(*dentry_path_raw)(const struct dentry *dentry, char *buf, int buflen) = NULL;
char *(*d_path)(const struct path *path, char *buf, int buflen) = NULL;
void (*path_put)(const struct path *path) = NULL;
void (*fput)(struct file *file) = NULL;

void *(*kf_vmalloc)(unsigned long size) = NULL;
void (*kf_vfree)(const void *addr) = NULL;

static char protected_directories[MAX_PATHS][PATH_MAX];
static int path_count = 0;

static bool check_path(struct filename *name){
    struct path path;
    char buf[PATH_MAX];
    int error;

    memset(buf, 0, PATH_MAX);

    error = kern_path(name->name, LOOKUP_FOLLOW, &path);
    if (error) {
        //pr_err("[yuuki] kern_path failed: %d\n", error);
        return false;
    }

    char* res = d_path(&path, buf, PATH_MAX);
    if (IS_ERR(res)) {
        pr_err("[yuuki] d_path failed: %ld\n", PTR_ERR(res));
        path_put(&path);
        return false;
    }

    path_put(&path);

    // user_path
    for (int i = 0; i < path_count; i++) {
        if (strncmp(res, protected_directories[i], getFolderLength(protected_directories[i])) == 0) {
            return true;
        }
    }

    return false;
}

static void do_unlinkat_before(hook_fargs2_t* args, void* udata) {
    struct filename* pathname = (struct filename*)args->arg1;
    if(check_path(pathname)){
        pr_info("[yuuki] Interception successful  --- rm file\n");
        args->skip_origin = true;
    }
}

static void do_rmdir_before(hook_fargs2_t* args, void* udata) {
    struct filename* pathname = (struct filename*)args->arg1;
    if(check_path(pathname)){
        pr_info("[yuuki] Interception successful  --- rm dir\n");
        args->skip_origin = true;
    }
}

static void vfs_rename_before(hook_fargs1_t* args, void* udata) {
    struct renamedata *rd = (struct renamedata*)args->arg0;
    struct path path;
    char buf[PATH_MAX];
    memset(buf, 0, PATH_MAX);

    //由于dentry_path_raw获取的路径不一定是绝对路径，所以需要反向遍历字符串比较
    //这里有点不严谨了，因为实在不知道怎么获取绝对路径了
    char* old_path = dentry_path_raw(rd->old_dentry, buf, PATH_MAX);

    if (IS_ERR(old_path)) {
        pr_err("[yuuki] old_path parse failed\n");
        return;
    }

    // user_path
    for (int i = 0; i < path_count; i++) {
        if (isSubstringAtEnd(old_path, protected_directories[i])) {
            pr_info("[yuuki] Interception successful  --- rename file\n");
            args->skip_origin = true;
        }
    }

}

static struct file *replace_do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op) {
    struct file *filp = backup_do_filp_open(dfd, pathname, op);
    if (likely(!IS_ERR(filp))) {
        char buf[PATH_MAX];
        memset(&buf, 0, PATH_MAX);
        char *currPath = d_path(&filp->f_path, buf, PATH_MAX);

        if ((op->open_flag & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_PATH | O_NOFOLLOW)) != 0 && strlen(currPath) > 13) { //我也不知道最后两个标志位是干嘛的，但是mt用了这两个，我也没有找到通过这俩实现文件读写的例子
            // user_path
            for (int i = 0; i < path_count; i++) {
                if (strncmp(currPath, protected_directories[i], strlen(protected_directories[i])) == 0) {
                    pr_info("[yuuki] Interception successful --- open file\n");
                    fput(filp);
                    return ERR_PTR(-EACCES);
                }
            }
        }
    }
    return filp;
}

static inline bool hook_do_unlinkat() {
    if(do_unlinkat){
        hook_err = hook_wrap(do_unlinkat, 2, do_unlinkat_before, NULL, NULL);
        if (hook_err != HOOK_NO_ERR) {
            pr_info("[yuuki] hook do_unlinkat, %llx, error: %d\n", do_unlinkat, hook_err);
        } else {
            return true;
        }
    } else {
        hook_err = HOOK_BAD_ADDRESS;
        pr_err("[yuuki] no symbol: do_unlinkat\n");
    }

    return false;
}

static inline bool hook_do_rmdir() {
    if(do_rmdir){
        hook_err = hook_wrap(do_rmdir, 2, do_rmdir_before, NULL, NULL);
        if (hook_err != HOOK_NO_ERR) {
            pr_info("[yuuki] hook do_rmdir, %llx, error: %d\n", do_rmdir, hook_err);
        } else {
            return true;
        }
    } else {
        hook_err = HOOK_BAD_ADDRESS;
        pr_err("[yuuki] no symbol: do_rmdir\n");
    }

    return false;
}

static inline bool hook_vfs_rename() {
    if(vfs_rename){
        hook_err = hook_wrap(vfs_rename, 1, vfs_rename_before, NULL, NULL);
        if (hook_err != HOOK_NO_ERR) {
            pr_info("[yuuki] hook vfs_rename, %llx, error: %d\n", vfs_rename, hook_err);
        } else {
            return true;
        }
    } else {
        hook_err = HOOK_BAD_ADDRESS;
        pr_err("[yuuki] no symbol: vfs_rename\n");
    }

    return false;
}

static inline bool hook_do_filp_open() {
    if (original_do_filp_open) {
        hook_err = hook((void *)original_do_filp_open, (void *)replace_do_filp_open, (void **)&backup_do_filp_open);
        if (hook_err != HOOK_NO_ERR) {
            pr_info("[yuuki] hook do_filp_open, %llx, error: %d\n", original_do_filp_open, hook_err);
        } else {
            return true;
        }
    } else {
        hook_err = HOOK_BAD_ADDRESS;
        pr_err("[yuuki] no symbol: do_filp_open\n");
    }
    return false;
}

static inline bool installHook() {
    bool ret = false;

    if (hook_err != HOOK_NO_ERR) {
        if (hook_do_filp_open() && hook_do_unlinkat() && hook_do_rmdir() && hook_vfs_rename()) {
            pr_info("[yuuki] hook installed...\n");
            ret = true;
        } else {
            pr_err("[yuuki] hook installation failed...\n");
        }
    } else {
        pr_info("[yuuki] hook already installed, skipping...\n");
        ret = true;
    }

    return ret;
}

static inline bool uninstallHook() {
    if (hook_err == HOOK_NO_ERR) {
        unhook((void*)do_unlinkat);
        unhook((void*)do_rmdir);
        unhook((void*)vfs_rename);
        unhook((void *)original_do_filp_open);
        hook_err = HOOK_NOT_HOOK;
        pr_info("[yuuki] hook uninstalled...\n");
    } else {
        pr_info("[yuuki] Maybe it's not hooked, skipping...\n");
    }
    return true;
}

static inline bool control_internal(bool enable) {
    return enable ? installHook() : uninstallHook();
}

static long mod_init(const char *args, const char *event, void *__user reserved){
    pr_info("[yuuki] Initializing...\n");
    pr_info("[yuuki] ARGS = %s\n", args);

    original_do_filp_open = (do_filp_open_func_t)kallsyms_lookup_name("do_filp_open");
    do_unlinkat = (typeof(do_unlinkat))kallsyms_lookup_name("do_unlinkat");
    do_rmdir = (typeof(do_rmdir))kallsyms_lookup_name("do_rmdir");
    vfs_rename = (typeof(vfs_rename))kallsyms_lookup_name("vfs_rename");

    kf_vmalloc = (typeof(kf_vmalloc))kallsyms_lookup_name("vmalloc");
    kf_vfree = (typeof(kf_vfree))kallsyms_lookup_name("vfree");
    long ret = 0;

    pr_info("[yuuki] Kernel Version: %x\n", kver);
    pr_info("[yuuki] Kernel Patch Version: %x\n", kpver);

    kern_path = (int (*)(const char *, unsigned int , struct path *))kallsyms_lookup_name("kern_path");
    if (!kern_path) {
        pr_info("[yuuki] kernel func: 'kern_path' does not exist!\n");
        goto exit;
    }

    dentry_path_raw = (typeof(dentry_path_raw))kallsyms_lookup_name("dentry_path_raw");
    if (!dentry_path_raw) {
        pr_info("[yuuki] kernel func: 'dentry_path_raw' does not exist!\n");
        goto exit;
    }

    d_path = (char *(*)(const struct path *, char *, int))kallsyms_lookup_name("d_path");
    if (!d_path) {
        pr_info("[yuuki] kernel func: 'd_path' does not exist!\n");
        goto exit;
    }

    path_put = (void (*)(const struct path *))kallsyms_lookup_name("path_put");
    if (!path_put) {
        pr_info("[yuuki] kernel func: 'path_put' does not exist!\n");
        goto exit;
    }

    fput = (void (*)(struct file *))kallsyms_lookup_name("fput");
    if (!fput) {
        pr_info("[yuuki] kernel func: 'fput' does not exist!\n");
        goto exit;
    }

    exit:
    return ret;
}

static long mod_control0(const char *args, char *__user out_msg, int outlen) {
    pr_info("[yuuki] kpm hello control0, args: %s\n", args);

    if(strncmp(args, "unhook", 6) == 0){
        path_count = 0;
        control_internal(false);
        pr_info("[yuuki] uninstalled hook.\n");

    } else {
        parse_paths(args, protected_directories, &path_count);

        for (int i = 0; i < path_count; i++) {
            pr_info("[yuuki] path %d: %s\n", i + 1, protected_directories[i]);
        }

        control_internal(true);
    }

    return 0;
}

static long mod_exit(void *__user reserved) {
    path_count = 0;
    control_internal(false);
    pr_info("[yuuki] mod_exit, uninstalled hook.\n");
    return 0;
}

KPM_INIT(mod_init);
KPM_CTL0(mod_control0);
KPM_EXIT(mod_exit);
