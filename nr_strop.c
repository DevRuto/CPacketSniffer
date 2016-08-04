//
// Created by Ruto on 8/2/2016.
//

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include "nr_strop.h"

char** strsplit(char* str, char* delimiter, int* outputlen) {
    *outputlen = 0;
    char* data = strdup(str);
    char* token;
    if (!data) return NULL;
    char** output;
    if (!(token = strtok(str, delimiter))) {
        return NULL;
    }
    output = malloc(++(*outputlen)*sizeof(char*));
    output[(*outputlen)-1] = strdup(token);
    while((token = strtok(NULL, delimiter))) {
        output = realloc(output, ++(*outputlen)*sizeof(char*));
        output[(*outputlen)-1] = strdup(token);
    }
    free(data);
    free(token);
    return output;
}

char* concat(char* str1, char* str2) {
    if (!str1 || !str2) {
        return NULL;
    }
    size_t len1 = strlen(str1), len2 = strlen(str2);
    char *buf = malloc(len1+len2+1);
    memcpy(buf, str1, len1);
    memcpy(buf+len1, str2, len2+1);
    buf[len1+len2] = 0;
    return buf;
}