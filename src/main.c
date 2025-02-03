/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>
#include <kputils.h>
#include <linux/string.h>
#include "module.h"

///< The name of the module, each KPM must has a unique name.
KPM_NAME("File_Guard");

///< The version of the module.
KPM_VERSION("1.21.51");

///< The license type.
KPM_LICENSE("GPL v2");

///< The author.
KPM_AUTHOR("yuuki & shapaozidex");

///< The description.
KPM_DESCRIPTION("Prevent your phone from being maliciously formatted");

/**
 * @brief hello world initialization
 * @details 
 * 
 * @param args 
 * @param reserved 
 * @return int 
 */
static long hello_init(const char *args, const char *event, void *__user reserved)
{
    hook_init();   
    pr_info("kpm hello init, event: %s, args: %s\n", event, args);
    pr_info("kernelpatch version: %x\n", kpver);
    return 0;
}

static long hello_control0(const char *args, char *__user out_msg, int outlen)
{
    pr_info("kpm hello control0, args: %s\n", args);
    hook_control0(args);
    char echo[64] = "echo: ";
    strncat(echo, args, 48);
    compat_copy_to_user(out_msg, echo, sizeof(echo));
    return 0;
}

static long hello_control1(void *a1, void *a2, void *a3)
{
    pr_info("kpm hello control1, a1: %llx, a2: %llx, a3: %llx\n", a1, a2, a3);
    return 0;
}

static long hello_exit(void *__user reserved)
{
    hook_deinit();
    pr_info("kpm hello exit\n");
    return 0;
}

KPM_INIT(hello_init);
KPM_CTL0(hello_control0);
KPM_CTL1(hello_control1);
KPM_EXIT(hello_exit);
