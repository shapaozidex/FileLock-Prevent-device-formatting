#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/fs.h>
#include <linux/kern_levels.h>
#include <linux/llist.h>
#include <ktypes.h>
#include <linux/string.h>
#include <linux/err.h>

KPM_NAME("AntiDelete");
KPM_VERSION("1.0.0");
KPM_AUTHOR("yuuki");
KPM_DESCRIPTION("Prevent your phone from being maliciously formatted");

#define PATH_MAX 256
#define LOOKUP_FOLLOW 0x0001

struct vfsmount;
struct super_block {

};

struct dentry {
    struct super_block *d_sb;
};

struct path {
    struct vfsmount *mnt;
    struct dentry *dentry;
};

struct file {
    union {
        struct llist_node    fu_llist;
        struct rcu_head      fu_rcuhead;
    } f_u;
    struct path     f_path;
    struct inode    *f_inode;
};

static hook_err_t hook_err = HOOK_NOT_HOOK;
static int (*do_unlinkat)(int dfd, struct filename *name);
static int (*do_rmdir)(int dfd, struct filename *name);

int (*kern_path)(const char *name, unsigned int flags, struct path *path) = NULL;
char *(*d_path)(const struct path *path, char *buf, int buflen) = NULL;
void (*path_put)(const struct path *path) = NULL;
void (*fput)(struct file *file) = NULL;

static bool check_path(struct filename *name)
{
    struct path path;
    char buf[PATH_MAX];
    int error;

    memset(buf, 0, PATH_MAX);
    error = kern_path(name->name, LOOKUP_FOLLOW, &path);
    if (error) {
        pr_err("[yuuki] kern_path failed: %d\n", error);
        return false;
    }

    char* res = d_path(&path, buf, PATH_MAX);
    if (IS_ERR(res)) {
        pr_err("[yuuki] d_path failed: %ld\n", PTR_ERR(res));
        path_put(&path);
        return false;
    }
    path_put(&path);

    if (strncmp(res, "/storage/emulated/0/Yuuki_Test/", 30) == 0) {//len - 1
        //pr_info("[yuuki] filepath = %s\n", res);
        return true;
    }

    return false;
}

static void* do_unlinkat_before(hook_fargs2_t* args, void* udata) {
    struct filename* pathname = (struct filename*)args->arg1;
    //pr_info("[yuuki] pathname = %s\n", pathname->name);
    if(check_path(pathname)){
        pr_info("[yuuki] 拦截成功=============================\n");
        args->skip_origin = true;
    }
}

static void* do_rmdir_before(hook_fargs2_t* args, void* udata) {
    struct filename* pathname = (struct filename*)args->arg1;
    pr_info("[yuuki] pathname = %s\n", pathname->name);
    if(check_path(pathname)){
        pr_info("[yuuki] 拦截成功=============================\n");
        args->skip_origin = true;
    }
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

static inline bool installHook() {
    bool ret = false;

    if (hook_err != HOOK_NO_ERR) {
        if (hook_do_unlinkat() && hook_do_rmdir()) {
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
    pr_info("[yuuki] args = %s\n", args);

    do_unlinkat = (typeof(do_unlinkat))kallsyms_lookup_name("do_unlinkat");
    do_rmdir = (typeof(do_rmdir))kallsyms_lookup_name("do_rmdir");

    long ret = 0;

    pr_info("[yuuki] Kernel Version: %x\n", kver);
    pr_info("[yuuki] Kernel Patch Version: %x\n", kpver);

    kern_path = (int (*)(const char *, unsigned int , struct path *))kallsyms_lookup_name("kern_path");
    if (!kern_path) {
        pr_info("[yuuki] kernel func: 'kern_path' does not exist!\n");
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
    control_internal(true);
    return 0;
}

static long mod_exit(void *__user reserved) {
    control_internal(false);
    pr_info("[yuuki] mod_exit, uninstalled hook.\n");
    return 0;
}

KPM_INIT(mod_init);
KPM_CTL0(mod_control0);
KPM_EXIT(mod_exit);
