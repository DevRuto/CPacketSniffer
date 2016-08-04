//
// Created by Ruto on 8/2/2016.
//

typedef struct nr_ip_address {
    char* ip_address;
    int port;
} nr_ip_address_t;

typedef struct nr_process {
    char* name;
    unsigned int pid;
    unsigned int memory_size;
    nr_ip_address_t* ip_addresses;
    unsigned int ip_count;
} nr_process_t;

typedef struct nr_process_list {
    nr_process_t* processes;
    size_t count;
} nr_process_list_t;

char* nr_exec(char*);

void nr_get_networked_processes_alloc(nr_process_list_t *list);
void nr_link_process_info(nr_process_list_t *list);
void nr_process_list_free(nr_process_list_t *list);