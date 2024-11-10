#include <linux/err.h>
#include "data_parse.h"

void parse_paths(char *args, char paths[MAX_PATHS][PATH_MAX], int *path_count) {
    char *line = args;
    char *next_line;
    int i = 0;

    while (line && i < MAX_PATHS) {
        next_line = strchr(line, '\n');
        if (next_line) {
            *next_line = '\0';  // 将换行符替换为字符串结束符
            next_line++;  // 移动到下一行的开始
        }

        strncpy(paths[i], line, PATH_MAX - 1);
        paths[i][PATH_MAX - 1] = '\0';  // 确保字符串以空字符结尾
        i++;

        line = next_line;
    }

    *path_count = i;
}

int getFolderLength(const char* path) {
    int len = strlen(path);
    int i;

    for (i = len - 1; i >= 0; --i)
        if (path[i] == '/')
            break;

    if (i >= 0)
        return i;

    return len;
}

int isSubstringAtEnd(const char* old_path, const char* user_path) {
    int lenA = strlen(old_path);
    int lenB = strlen(user_path);

    if (lenA > lenB)
        return false;

    for (int i = 0; i < lenA; ++i)
        if (user_path[lenB - lenA + i] != old_path[i])
            return false;

    return true;
}