#include <stdio.h>
#include <stdint.h>
#include "hdr.h"
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <time.h>

typedef struct ARP_Packet{
    Ether eth;
    ARP arp;
}ARP_packet;

void usage() {

    printf("syntax: ip_scan <interface> \n");
    printf("sample: ip_scan wlan0\n");
}

uint32_t get_ip(char *ip_string){

    unsigned int a, b, c, d;

    sscanf(ip_string,"%u.%u.%u.%u", &a, &b, &c, &d);
    return ((a << 24) | (b << 16) | (c << 8) | d);
}

uint32_t get_my_ip(char *dev){

    struct ifreq ifr;
    char ipstr[40];
    int s;

    s = socket(AF_INET,SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(s, SIOCGIFADDR, &ifr)<0)
        printf("ERROR");
    else
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,ipstr,sizeof(struct sockaddr));
    return get_ip(ipstr);
}

void get_my_mac(char* dev, uint8_t *mac){

    struct ifreq ifr;
    int s;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev,IFNAMSIZ);
    if(ioctl(s,SIOCGIFHWADDR, &ifr) <0)
        printf("ERROR");
    else
        memcpy(mac,ifr.ifr_hwaddr.sa_data,6);
}

void find_ip(pcap_t* handle, uint8_t *source_mac, uint32_t source_ip){

    ARP_Packet arp_request;
    ARP_Packet *capture;
    unsigned int a,b,c;
    int check[244];
    int timeout = 15;
    struct timeval start, end, current;

    memset(check,0,sizeof(check));
    memset(arp_request.eth.des, 0xFF, 6);
    memcpy(arp_request.eth.src,source_mac,sizeof(uint8_t)*6);
    arp_request.eth.pkt_type = htons(0x0806);

    arp_request.arp.hd_type = htons(0x0001);
    arp_request.arp.prc_type = htons(0x0800);
    arp_request.arp.hd_addr_len = 0x06;
    arp_request.arp.prc_addr_len = 0x04;
    arp_request.arp.opcode = htons(0x0001);

    memcpy(arp_request.arp.src_mac,source_mac,sizeof(uint8_t)*6);
    arp_request.arp.src_ip = htonl(source_ip);

    memset(arp_request.arp.tag_mac, 0x00, 6);

    for(int i=1; i<255; i++){
        a = ntohl(source_ip) & 0xFF;
        b = ntohl(source_ip << 8) & 0xFF;
        c = ntohl(source_ip <<16) & 0xFF;
        arp_request.arp.tag_ip = htonl(((a << 24) | (b << 16) | (c << 8) | i));
        struct pcap_pkthdr* header;
        const u_char* data;
        int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arp_request), sizeof(ARP_Packet));
        if (res2 != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res2, pcap_geterr(handle));
        }
//        printf("Send to IP : %d.%d.%d.%d\n",ntohl(arp_request.arp.tag_ip<<24) & 0xFF, ntohl(arp_request.arp.tag_ip <<16)&0xFF,ntohl(arp_request.arp.tag_ip <<8)&0xFF,ntohl(arp_request.arp.tag_ip )&0xFF);

        int res = pcap_next_ex(handle, &header, &data);
        if(res == 0) continue;
        if(res == -1 || res == -2){
            printf("pcap_next_ex return %d(%s)\n",res, pcap_geterr(handle));
        }

        capture = (ARP_Packet*)data;
        if(ntohs(capture->eth.pkt_type) == 0x0806){
            if(ntohs(capture->arp.opcode) == 0x0002){
                if(check[ntohl(capture->arp.src_ip )&0xFF] == 0){
                    printf("IP : %d.%d.%d.%d\n",ntohl(capture->arp.src_ip <<24) & 0xFF, ntohl(capture->arp.src_ip <<16)&0xFF,ntohl(capture->arp.src_ip <<8)&0xFF,ntohl(capture->arp.src_ip )&0xFF);
                    printf("MAC : %02x:%02x:%02x:%02x:%02x:%02x \n",capture->arp.src_mac[0], capture->arp.src_mac[1],capture->arp.src_mac[2],capture->arp.src_mac[3],capture->arp.src_mac[4],capture->arp.src_mac[5]);
                    check[ntohl(capture->arp.src_ip )&0xFF] = 1;
                }
            }
        }
    }
    printf("Finish send packet\n");
    printf("Packet capture during 15seconds\n");
    gettimeofday(&start, 0);
    gettimeofday(&current,0);
    end.tv_sec = start.tv_sec + timeout;
    while(current.tv_sec - end.tv_sec < 0){
        gettimeofday(&current,0);

        if(ntohs(capture->eth.pkt_type) == 0x0806){
            if(ntohs(capture->arp.opcode) == 0x0002){
                if(check[ntohl(capture->arp.src_ip )&0xFF] == 0){
                    printf("IP : %d.%d.%d.%d\n",ntohl(capture->arp.src_ip <<24) & 0xFF, ntohl(capture->arp.src_ip <<16)&0xFF,ntohl(capture->arp.src_ip <<8)&0xFF,ntohl(capture->arp.src_ip )&0xFF);
                    printf("MAC : %02x:%02x:%02x:%02x:%02x:%02x \n",capture->arp.src_mac[0], capture->arp.src_mac[1],capture->arp.src_mac[2],capture->arp.src_mac[3],capture->arp.src_mac[4],capture->arp.src_mac[5]);
                    check[ntohl(capture->arp.src_ip )&0xFF] = 1;
                }
            }
        }
    }
}

int main(int argc, char*argv[]){
    if(argc != 2){
        usage();
        return -1;
    }
    uint32_t my_ip;
    uint8_t my_mac[6];

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    my_ip = get_my_ip(dev);
    printf("My IP : %d.%d.%d.%d\n",ntohl(my_ip) & 0xFF, ntohl(my_ip <<8)&0xFF,ntohl(my_ip <<16)&0xFF,ntohl(my_ip <<24)&0xFF);
    get_my_mac(dev,my_mac);
    printf("My MAC : %02x:%02x:%02x:%02x:%02x:%02x \n",my_mac[0], my_mac[1],my_mac[2],my_mac[3],my_mac[4],my_mac[5]);

    pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
    if(handle == nullptr){
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    find_ip(handle,my_mac,my_ip);
    pcap_close(handle);
}
