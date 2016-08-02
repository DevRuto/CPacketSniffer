//
// Created by Ruto on 8/1/2016.
//

#include "nr_packet_interface.h"
#define IPTOSBUFFERS    12

char *iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (short) (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

pcap_t *nr_open_current_device_adapter(int snaplen, pcap_addr_t ** sockaddr) {
    pcap_if_t *devices;
    pcap_if_t *device;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &devices, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
        return 0;
    }

    // Return first interface with an address
    for (device = devices; device; device = device->next) {
        if (device->description) {
            pcap_addr_t *addr;
            for (addr = device->addresses; addr; addr = addr->next) {
                if (addr->addr->sa_family == AF_INET) { // IPv4 addr
                    if (addr->addr) {
                        (*sockaddr) = nr_get_device_ip_interface(device);
                        pcap_t *handle;
                        handle = pcap_open(device->name, snaplen, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
                        return handle;
                    }
                }
            }
        }
    }
    return 0;
}

pcap_addr_t * nr_get_device_ip_interface(pcap_if_t *dev) {
    return dev->addresses->next;
}

char* nr_parse_ip(pcap_addr_t* t) {
    return iptos(((struct sockaddr_in *)t->addr)->sin_addr.s_addr);
}

void nr_apply_packet_filter(pcap_t *handle, char* filter, struct bpf_program *code, u_int netmask) {
    if (pcap_compile(handle, (struct bpf_program *) &code, filter, 1, netmask) < 0) {
        fprintf(stderr, "\nUnable to compile packet filter\n");
        return;
    }
    if (pcap_setfilter(handle, (struct bpf_program *) &code) < 0) {
        fprintf(stderr, "\nUnable to set filter\n");
        return;
    }
}