#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <string.h>

/* Ethernet header */
struct ethheader {
    u_char ether_dhost[6]; // destination MAC
    u_char ether_shost[6]; // source MAC
    u_short ether_type;    // IP ARP
}; 

/* IP header */
struct ipheader {
    unsigned char      iph_ihl:4, iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag:3, iph_offset:13;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    struct in_addr     iph_sourceip;
    struct in_addr     iph_destip;
};

/* TCP header */
struct tcpheader {
    u_short th_sport;
    u_short th_dport;
    u_int   th_seq;
    u_int   th_ack;
    u_char  th_offx2;
    u_char  th_flags;
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    // 0x0800 == IP
    if (ntohs(eth->ether_type) == 0x0800) {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        if (ip->iph_protocol != IPPROTO_TCP) return;

        int ip_header_len = ip->iph_ihl * 4;
        struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
        int tcp_header_len = ((tcp->th_offx2 & 0xf0) >> 4) * 4;

        const u_char *payload = packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len;
        int total_len = ntohs(ip->iph_len);
        int payload_len = total_len - ip_header_len - tcp_header_len;

        printf("\n===== TCP Packet =====\n");

        // MAC
        printf("Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
               eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
        printf("Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
               eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

        // IP
        printf("From: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("To  : %s\n", inet_ntoa(ip->iph_destip));

        // TCP
        printf("Src Port: %d\n", ntohs(tcp->th_sport));
        printf("Dst Port: %d\n", ntohs(tcp->th_dport));

        // Message (Payload)
        if (payload_len > 0) {
            printf("Payload (%d bytes): ", payload_len);
            for (int i = 0; i < payload_len && i < 100; i++) {
                printf("%c", isprint(payload[i]) ? payload[i] : '.');
            }
            printf("\n");
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";  // TCP only
    bpf_u_int32 net;

    // Step 1: Open session
    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 1;
    }

    // Step 2: Compile & apply filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1 || pcap_setfilter(handle, &fp) == -1) {
        pcap_perror(handle, "Error");
        return 2;
    }

    // Step 3: Loop to capture packets
    pcap_loop(handle, 10, got_packet, NULL); // 10 packets

    pcap_close(handle);
    return 0;
}
