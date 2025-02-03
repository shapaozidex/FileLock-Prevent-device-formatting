#ifndef _KPM_FILE_H
#define _KPM_FILE_H

#include <ktypes.h>

struct open_flags {
    int open_flag;
    umode_t mode;
    int acc_mode;
    int intent;
    int lookup_flags;
};

#endif //_KPM_FILE_H