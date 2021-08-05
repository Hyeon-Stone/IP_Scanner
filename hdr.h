#pragma once
#include <stdio.h>
#include <stdint.h>
#pragma pack(push, 1)
typedef struct ETHER{
    uint8_t des[6];
    uint8_t src[6];
    uint16_t pkt_type;
}Ether;
typedef struct IP{
    uint8_t verison_hl;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t src_ip;
  //uint8_t src_ip[4];
    uint32_t des_ip;
  //uint8_t des_ip[4];
}IP;
typedef struct TCP{
    uint16_t src_port;
    uint16_t des_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t offset_reserve;
    uint8_t flag;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
}TCP;
typedef struct ARP{
    uint16_t hd_type;
    uint16_t prc_type;
    uint8_t hd_addr_len;
    uint8_t prc_addr_len;
    uint16_t opcode;
    uint8_t src_mac[6];
//    uint8_t src_ip[4];
    uint32_t src_ip;
    uint8_t tag_mac[6];
//    uint8_t tag_ip[4];
    uint32_t tag_ip;
}ARP;
#pragma pack(pop)
