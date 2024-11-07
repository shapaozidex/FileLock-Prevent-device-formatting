#include "data_parse.h"

void parse_paths(char *args, char paths[MAX_PATHS][PATH_MAX], int *path_count) {
    char *line = args;
    char *next_line;
    int i = 0;

    while (line && i < MAX_PATHS) {
        next_line = strchr(line, '\n');
        if (next_line) {
            *next_line = '\0'; 
            next_line++;
        }

        strncpy(paths[i], line, PATH_MAX - 1);
        paths[i][PATH_MAX - 1] = '\0';
        i++;

        line = next_line;
    }

    *path_count = i;
}