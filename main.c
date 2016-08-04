//
// Created by Ruto on 8/1/2016.
//
#define HAVE_REMOTE

#include <ws2tcpip.h>
#include "pcap.h"
#include "nr_packet_interface.h"
#include "nr_network_processes.h"
#include "nr_strop.h"

#include <winsock.h>
#include <afxres.h>
#include <ctype.h>


#endif

void callback(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

//netstat –ano ¦find /i “listening”

void main() {
    nr_process_list_t list;
    int procindex, ii, input;
    nr_process_t *process;
    while (1) {
        nr_get_networked_processes_alloc(&list);
        nr_link_process_info(&list);
        printf("Total applications: %d\n", list.count);
        for (procindex = 0; procindex < list.count; procindex++) {
            if (!(list.processes[procindex].name && list.processes[procindex].ip_addresses)) continue;
            printf("%d: Name: %s | Count: %d\n", procindex + 1, list.processes[procindex].name, list.processes[procindex].ip_count);
            fflush(stdout);
            /*if (list.processes[procindex].ip_count > 0)
            for (ii = 0; ii < list.processes[procindex].ip_count; ii++) {
                if (list.processes[procindex].ip_addresses[ii].ip_address)
                    printf("\t%d: %s\n", ii, list.processes[procindex].ip_addresses[ii].ip_address);
            }*/
        }
        puts("Enter the integer of the application you wish to capture packets from (0 to quit): ");
        fflush(stdout);
        if (scanf("%d", &input) == EOF || input > list.count) {
            nr_process_list_free(&list);
            continue;
        }
        if (!input) break;

        process = &list.processes[input-1];

        printf("Selected process: %s\n", process->name);

        puts("\n");
        break;
    }
    fflush(stdout);
    puts("\nBegin Listen\n");

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
    int len;
    char* ip = strsplit(process->ip_addresses[0].ip_address, ":", &len)[0];
    printf("Filter ip: %s\n", ip);
    nr_apply_packet_filter(pcaphandle, concat("host ", ip) /*"ip and tcp"*/, &fcode, netmask);
    puts("\nListening..\n");

    pcap_loop(pcaphandle, 0, callback, NULL);

    nr_process_list_free(&list);
}

//START TYPES
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};

void print_payload(const char* payload, int payloadsize) {
    int i;
    for (i = 0; i < payloadsize; i++) {
        if (isprint(*payload))
            printf("%c", *payload);
        else
            printf(".");
        payload++;
    }
    puts("\n");
}

void callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char*
packet)
{
    static int count = 1;
    count++;

    const struct sniff_ip *ip = (struct sniff_ip*)(packet+SIZE_ETHERNET);
    if (ip->ip_p != IPPROTO_TCP) return;
    // YES TCP
    int size_ip = IP_HL(ip)*4;
    const struct sniff_tcp *tcp = (struct sniff_tcp*)(packet+SIZE_ETHERNET+size_ip);
    int size_tcp = TH_OFF(tcp)*4;
    printf("Packet Count: %d\n", count);

    int payload_size = ntohs(ip->ip_len) - (size_ip+size_tcp);
    const char* payload = (const char *)(packet+SIZE_ETHERNET+size_ip+size_tcp);
    print_payload(payload, payload_size);
    fflush(stdout);
}

