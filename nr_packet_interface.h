//
// Created by Ruto on 8/1/2016.
//

#define HAVE_REMOTE
#define NR_MAX_TCP_SIZE 65536
#include "pcap.h"

typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

pcap_t *nr_open_current_device_adapter(int, pcap_addr_t **);
pcap_addr_t * nr_get_device_ip_interface(pcap_if_t *dev);
char* nr_parse_ip(pcap_addr_t *);
char *iptos(u_long in);

void nr_apply_packet_filter(pcap_t *handle, char* filter, struct bpf_program *code, u_int netmask);