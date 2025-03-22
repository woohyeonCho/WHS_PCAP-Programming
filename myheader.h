#ifndef MYHEADER_H
#define MYHEADER_H

#include <pcap.h>

// Ethernet 헤더 (14바이트)
struct ethheader {
    u_char dst_mac[6];
    u_char src_mac[6];
    u_short type;
};

// IP 헤더
struct ipheader {
    u_char  iph_verlen;        // Version (4 bits) + Internet header length (4 bits)
    u_char  iph_tos;           // Type of service
    u_short iph_len;           // Total length
    u_short iph_ident;         // Identification
    u_short iph_flags;         // Flags + Fragment offset
    u_char  iph_ttl;           // Time to live
    u_char  iph_protocol;      // Protocol
    u_short iph_chksum;        // Header checksum
    struct  in_addr iph_src;   // Source IP
    struct  in_addr iph_dest;  // Destination IP
};

// TCP 헤더
struct tcpheader {
    u_short th_sport;          // Source port
    u_short th_dport;          // Destination port
    u_int   th_seq;            // Sequence number
    u_int   th_ack;            // Acknowledgement number
    u_char  th_offx2;          // Data offset, reserved
    u_char  th_flags;
    u_short th_win;            // Window
    u_short th_sum;            // Checksum
    u_short th_urp;            // Urgent pointer
};

#endif
