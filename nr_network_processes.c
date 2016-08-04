//
// Created by Ruto on 8/2/2016.
//

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "nr_network_processes.h"
#include "nr_strop.h"

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

nr_process_t *nr_get_process_from_list(nr_process_list_t* list, int pid) {
    if (list->count == 0) return NULL;
    int i;
    for (i = 0; i < list->count; i++)
        if (list->processes[i].pid == pid)
            return &list->processes[i];
    return NULL;
}

void nr_get_networked_processes_alloc(nr_process_list_t *list) {
    char *cmd = "netstat -no -p tcp | find /I \"TCP\"";
    char* output = nr_exec(cmd);
    char *delimiter = "\n";
    int lncount, lnindex, splitcount;
    char** elements;
    char** lines = strsplit(output, delimiter, &lncount);
    free(output);
    if (!lines) return;
    list->processes = malloc(sizeof(nr_process_t*));
    list->count = 0;

    int pid, curindex = 0;
    nr_process_t *process;
    for (lnindex = 0; lnindex < lncount; lnindex++) {
        elements = strsplit(lines[lnindex], " ", &splitcount);
        pid = atoi(elements[4]);
        if (!(process = nr_get_process_from_list(list, pid))) {
            list->processes = realloc(list->processes, ++list->count*sizeof(*list->processes));
            process = &list->processes[list->count-1];
            process->pid = (unsigned int) pid;
            process->ip_count = 0;
        }
        if (!process->ip_count) {
            process->ip_count = 0;
            curindex = process->ip_count++;
            process->ip_addresses = malloc(sizeof(nr_ip_address_t *));
        } else {
            curindex = process->ip_count++;
            process->ip_addresses = realloc(process->ip_addresses, process->ip_count * sizeof(*process->ip_addresses));
        }
        process->ip_addresses[curindex].ip_address = strdup(elements[2]);

        free(elements);
    }
    free (lines);
}

void nr_link_process_info(nr_process_list_t *list) {
    if (list->count == 0) return;
    char *cmd = "tasklist | find /I \"Console\"";
    char *output = nr_exec(cmd);
    char *delimiter = "\n";
    int lncount, lnindex, splitcount;
    char** elements;
    char** lines = strsplit(output, delimiter, &lncount);
    free(output);
    if (!lines) return;

    nr_process_t *process;
    for (lnindex = 0; lnindex < lncount; lnindex++) {
        elements = strsplit(lines[lnindex], " ", &splitcount);
        if (!(process = nr_get_process_from_list(list, atoi(elements[1]))))
            continue;
        process->name = strdup(elements[0]);
        process->memory_size = 4321;
        free(elements);
    }
    free(lines);
}

void nr_process_list_free(nr_process_list_t *list) {
    int i;
    for (i = 0; i < list->count; i++)
        free(list->processes[i].ip_addresses);
    free(list->processes);
}