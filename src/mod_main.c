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

int (*kern_path)(const char *name, unsigned int flags, struct path *path) = NULL;
char *(*d_path)(const struct path *path, char *buf, int buflen) = NULL;
void (*path_put)(const struct path *path) = NULL;
void (*fput)(struct file *file) = NULL;

static char protected_directories[MAX_PATHS][PATH_MAX];
static int path_count = 0;

static bool check_path(struct filename *name){
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

    // default_path
    if (strncmp(res, "/storage/emulated/0/Yuuki_Test/", 30) == 0) {//len - 1
        //pr_info("[yuuki] filepath = %s\n", res);
        return true;
    }

    // user_path
    for (int i = 0; i < path_count; i++) {
        if (strncmp(res, protected_directories[i], strlen(protected_directories[i]) - 1) == 0) {
            return true;
        }
    }

    return false;
}

static void* do_unlinkat_before(hook_fargs2_t* args, void* udata) {
    struct filename* pathname = (struct filename*)args->arg1;
    //pr_info("[yuuki] pathname = %s\n", pathname->name);
    if(check_path(pathname)){
        pr_info("[yuuki] Interception successful  --- rm file\n");
        args->skip_origin = true;
    }
}

static void* do_rmdir_before(hook_fargs2_t* args, void* udata) {
    struct filename* pathname = (struct filename*)args->arg1;
    //pr_info("[yuuki] pathname = %s\n", pathname->name);
    if(check_path(pathname)){
        pr_info("[yuuki] Interception successful  --- rm dir\n");
        args->skip_origin = true;
    }
}


static struct file *replace_do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op) {
    struct file *filp = backup_do_filp_open(dfd, pathname, op);
    if (likely(!IS_ERR(filp))) {
        char buf[PATH_MAX];
        memset(&buf, 0, PATH_MAX);
        char *currPath = d_path(&filp->f_path, buf, PATH_MAX);

        if ((op->open_flag & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)) != 0 && strlen(currPath) > 13) {
            // default_path
            if (unlikely(strncmp(currPath, "/dev/block/sd", 13) == 0) || unlikely(strncmp(currPath, "/dev/block/loop", 15) == 0) || unlikely(strncmp(currPath, "/dev/block/dm-", 14) == 0)) {
                pr_err("[yuuki] Interception  --- open file\n");
                fput(filp);
                return ERR_PTR(-EACCES);
            }

            // user_path
            for (int i = 0; i < path_count; i++) {
                if (strncmp(currPath, protected_directories[i], strlen(protected_directories[i])) == 0) {
                    pr_err("[yuuki] Interception successful --- open file\n");
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
        if (hook_do_filp_open() && hook_do_unlinkat() && hook_do_rmdir()) {
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

    parse_paths(args, protected_directories, &path_count);

    for (int i = 0; i < path_count; i++) {
        pr_info("[yuuki] path %d: %s\n", i + 1, protected_directories[i]);
    }

    control_internal(true);
    return 0;
}

static long mod_exit(void *__user reserved) {
    path_count = 0;
    control_internal(false);
    pr_info("[yuuki] anti_format_device_exit, uninstalled hook.\n");
    return 0;
}

KPM_INIT(mod_init);
KPM_CTL0(mod_control0);
KPM_EXIT(mod_exit);