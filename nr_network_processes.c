//
// Created by Ruto on 8/2/2016.
//

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "nr_network_processes.h"
#include "nr_strop.h"

char* concat(char *str1, char *str2) {
    if (!str1 || !str2) {
        return NULL;
    }
    size_t len1 = strlen(str1), len2 = strlen(str2);
    char *str = malloc(len1 + len2 + 1);
    memcpy(str, str1, len1);
    memcpy(str + len1, str2, len2);
    str[len1 + len2] = 0;
    return str;
}

char* nr_exec(char* cmd) {
    char buffer[256];
    FILE *pipe = popen(cmd, "r");
    if (!pipe) {
        puts ("Error on popen()");
        return NULL;
    }
    char* output = "";
    while (fgets(buffer, 256, pipe) != NULL) {
        output = concat(output, buffer);
    }
    return output;
}

nr_process_list_t *nr_get_processes() {
    nr_process_list_t* list;
    list = malloc(sizeof(nr_process_t*));
    char* cmd = "tasklist | find /I \"Console\"";
    char *str = nr_exec(cmd);
    char* delimiter = "\n";
    int linecount, lnindex;
    char** split = strsplit(str, delimiter, &linecount);
    if (!split) return NULL;
    list->processes = malloc(linecount*sizeof(nr_process_t*));
    int splitcount;
    char** elements;
    list->count = (size_t) linecount;
    for (lnindex = 0; lnindex < linecount; lnindex++) {
        elements = strsplit(split[lnindex], " ", &splitcount);
        list->processes[lnindex].name = strdup(elements[0]);
        list->processes[lnindex].pid = (unsigned int) atoi(elements[1]);
        //list->processes[lnindex].memory_size = 1234;
       // if (elements[5][0] == 'K')
       //     list->processes[lnindex].pid = list->processes[lnindex].pid * 1000;
        free(elements);
        //printf("%d: Name: %s\t\tPid: %d\t\tSize: %d\n", lnindex, process.name, process.pid, process.memory_size);
    }
    free (cmd);
    free(str);
    free(delimiter);
    free(split);
    return list;
}