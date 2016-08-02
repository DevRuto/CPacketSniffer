//
// Created by Ruto on 8/1/2016.
//
#define HAVE_REMOTE

#include <ws2tcpip.h>
#include "pcap.h"
#include "nr_packet_interface.h"
#include "nr_network_processes.h"
#include "nr_strop.h"

#ifndef WIN32
#include <sys/socket.h>
    #include <netinet/in.h>
#else
#include <winsock.h>
#include <afxres.h>

#endif

void callback(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

//netstat –ano ¦find /i “listening”

void main() {
    nr_process_list_t* processes = nr_get_processes();
    int i;
    for (i = 0; i < processes->count; i++) {
        nr_process_t proc = processes->processes[i];
        printf("%d: Name: %s\tPid: %d\tSize: %d\n", i, proc.name, proc.pid, proc.memory_size);
    }
    printf("\n");
}

void main5() {
    char* cmd = "tasklist | find /I \"Console\"";
    char *str = nr_exec(cmd);
    char* delimiter = "\n";
    int outputlen, i;
    char** split = strsplit(str, delimiter, &outputlen);
    for (i = 0; i < outputlen; i++) {
        int subout, ii;
        char** split2 = strsplit(split[i], " ", &subout);
        for (ii = 0; ii < subout; ii++) {
            printf("%s ", split2[ii]);
        }
        puts("\n");
    }
}

void main2()
{
    //char* cmd = "tasklist | find /I \"Console\"";
    char* cmd = "netstat -no -p tcp | find \"TCP\"";
    char* tasklist = nr_exec(cmd);
    printf("Output: %s", tasklist);
    free(tasklist);
}

void main3()
{
    pcap_t *pcaphandle;
    pcap_addr_t *addr;
    struct bpf_program fcode;

    if ((pcaphandle = nr_open_current_device_adapter(NR_MAX_TCP_SIZE, &addr)) == NULL) {
        fprintf(stderr, "\nUnable to open adapter. \n");
        return;
    }
    if (addr) {
        printf("YES\nIp: %s\n", nr_parse_ip(addr));
    } else {
        puts("NO\n");
        return;
    }

    u_int netmask;
    if (addr != NULL) {
        netmask = ((struct sockaddr_in *)(addr->netmask))->sin_addr.S_un.S_addr;
    } else {
        netmask = 0xffffff;
    }
    printf("Netmask: %s\n", iptos(netmask));
    nr_apply_packet_filter(pcaphandle, "ip and tcp", &fcode, netmask);
    puts("\nListening..\n");

    pcap_loop(pcaphandle, 0, callback, NULL);
}

void callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char*
packet)
{
    static int count = 1;
    fprintf(stdout, "%3d, ", count);
    fflush(stdout);
    count++;
}

