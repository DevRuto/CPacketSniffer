//
// Created by Ruto on 8/2/2016.
//

typedef struct nr_process {
    char* name;
    unsigned int pid;
    unsigned int memory_size;
} nr_process_t;

typedef struct nr_process_list {
    nr_process_t* processes;
    size_t count;
} nr_process_list_t;

char* nr_exec(char*);

nr_process_list_t *nr_get_processes();
