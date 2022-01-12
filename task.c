#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>    
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>

#include "oui.h"

#define BUF_SIZE 100

#define IPV4_LENGTH 4
#define ARP_REQUEST 0x01
#define ARP_REPLY   0x02

#define MAC_PRINTF_FORMAT  "%02X:%02X:%02X:%02X:%02X:%02X"
#define MAC_PRINTF_ARGS(p) ((unsigned) ((uint8_t*)(p))[0]), \
                           ((unsigned) ((uint8_t*)(p))[1]), \
                           ((unsigned) ((uint8_t*)(p))[2]), \
                           ((unsigned) ((uint8_t*)(p))[3]), \
                           ((unsigned) ((uint8_t*)(p))[4]), \
                           ((unsigned) ((uint8_t*)(p))[5])

struct arphdr {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t hw_len;
    uint8_t proto_len;
    uint16_t opcode;
    uint8_t sender_mac[ETH_ALEN];
    uint8_t sender_ip[IPV4_LENGTH];
    uint8_t target_mac[ETH_ALEN];
    uint8_t target_ip[IPV4_LENGTH];
} __attribute__((packed));

void parse_vendor(uint8_t *mac)
{
    int a = 0;
    int c;
    int b = __vendors_size;
    int cmp;
    int idx = -1;
    char first_three_mac_bytes[9]; /* XX:XX:XX + '\0' */

    snprintf(first_three_mac_bytes, 9, "%02X:%02X:%02X",
             mac[0], mac[1], mac[2]);

    while (a + 1 < b) {
        c = (a + b) / 2;

        cmp = strncmp(first_three_mac_bytes, __vendors[c][0], 9);
        if (cmp == 0){
            idx = c;
            break;
        }
        else if (cmp < 0)
            b = c;
        else if (cmp > 0)
            a = c;
    }

    if (idx == -1)
        printf("Vendor undefined\n");
    else
        printf("%s\n", __vendors[idx][1]);
}

int parse_arp(struct arphdr *arp)
{
    printf("=====================================\n");
    if(arp->opcode == htons(ARP_REQUEST)){
        printf("Got ARP request\n");
        printf("Sender mac: "MAC_PRINTF_FORMAT" ",
                MAC_PRINTF_ARGS(arp->sender_mac));
        parse_vendor(arp->sender_mac);
        printf("Target mac is broadcast \n");
    }
    else if(arp->opcode == htons(ARP_REPLY)){
        printf("Got ARP reply\n");
        printf("Sender mac: "MAC_PRINTF_FORMAT" ",
                MAC_PRINTF_ARGS(arp->sender_mac));
        parse_vendor(arp->sender_mac);
        printf("Target mac: "MAC_PRINTF_FORMAT" ",
                MAC_PRINTF_ARGS(arp->target_mac));
        parse_vendor(arp->target_mac);
    } else{
        fprintf(stderr, "Ivalid ARP opcode -- 0x%02X\n", ntohs(arp->opcode));
        return -1;
    }
    
    return 0;
}

int main(int argc, char *argv[]){
    int                 fd;
    int                    retval;
    struct sockaddr_ll  saddr_ll;
    unsigned int        ifindex;
    char                 buf[BUF_SIZE];
    struct ethhdr        *eth_hdr;
    struct arphdr        *arp_hdr;

    if(argc != 2) {
        fprintf(stderr, "Usage: %s <interface name>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    ifindex = if_nametoindex(argv[1]);
    if (ifindex == 0) {
        perror("if_nametoindex");
        exit(EXIT_FAILURE);
    }

    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(fd == -1){
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&saddr_ll, 0, sizeof(struct sockaddr_ll));
    saddr_ll.sll_family = AF_PACKET;
    saddr_ll.sll_ifindex = ifindex;

    retval = bind(fd, (struct sockaddr *)&saddr_ll,
                  sizeof(struct sockaddr_ll));
    if (retval == -1) {
        perror("bind");
        close(fd);
        exit(EXIT_FAILURE);
    }

    while (1){
        retval = read(fd, buf, BUF_SIZE);
        if (retval == -1) {
            perror("read");
            close(fd);
            exit(EXIT_FAILURE);
        }

        if(retval < sizeof(struct ethhdr)){
            fprintf(stderr, "Got corrupted packet, skipping\n");
            continue;
        }

        eth_hdr = (struct ethhdr *)buf;
        
        if(eth_hdr->h_proto == htons(ETH_P_ARP)){
            arp_hdr = (struct arphdr *)(buf + sizeof(struct ethhdr));
            retval = parse_arp(arp_hdr);
            if (retval == -1)
                continue;
        }    
    }

return 0;
}
