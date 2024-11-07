#ifndef SYS_SECURITY_DATA_PARSE_H
#define SYS_SECURITY_DATA_PARSE_H

#include <linux/string.h>
#include "file.h"

void parse_paths(char *args, char paths[MAX_PATHS][PATH_MAX], int *path_count);

#endif
