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
    output[(*outputlen)-1] = token;
    while((token = strtok(NULL, delimiter))) {
        output = realloc(output, ++(*outputlen)*sizeof(char*));
        output[(*outputlen)-1] = token;
    }
    free(data);
    return output;
}