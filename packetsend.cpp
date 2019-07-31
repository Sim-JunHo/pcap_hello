#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>
#include "protocol/all.h"

void usage()
{
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}

int main(int argc, char *argv[])
{
    char interface[IFNAMSIZ];
    char senderIPstr[15];
    char targetIPstr[15];
    char senderMACstr[17];
    char targetMACstr[17];
    ip_addr senderIP;
    ip_addr targetIP;
    mac_addr senderMAC;
    mac_addr targetMAC;

    if (argc == 6)
    {
        strncpy(interface, argv[1], IFNAMSIZ);
        strncpy(senderIPstr, argv[2], strlen(argv[2]));
        strncpy(senderMACstr, argv[3], strlen(argv[3]));
        strncpy(targetIPstr, argv[4], strlen(argv[4]));
        strncpy(targetMACstr, argv[5], strlen(argv[5]));

    }
    else {
        printf("error\n");
        return -1;
    }

    if(4 != sscanf(senderIPstr, "%hhx.%hhx.%hhx.%hhx", &senderIP.a, &senderIP.b, &senderIP.c, &senderIP.d)) {
        return -1;
    }
    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    while (true)
    {
        uint8_t buffer[1500];
        int packetIndex = 0;
        ether_header eth;
        eth.ether_type = htons(ETHERTYPE_ARP);
        mac_addr src;
		src.oui[0] = 0x00;
		src.oui[1] = 0x0C;
		src.oui[2] = 0x29;
		src.nic[0] = 0x1F;
		src.nic[1] = 0x45;
		src.nic[2] = 0xCF;
		eth._src = src;

		mac_addr dest;
		dest.oui[0] = 0xFF;
		dest.oui[1] = 0xFF;
		dest.oui[2] = 0xFF;
		dest.nic[0] = 0xFF;
		dest.nic[1] = 0xFF;
		dest.nic[2] = 0xFF;
		eth._dst = dest;

        memcpy(buffer, &eth, sizeof(ether_header));
        packetIndex += sizeof(ether_header);

        /* ARP ~~ */
        arp_header arp;
        arp.sender_mac;
        memcpy(buffer, &arp, sizeof(arp_header));
        packetIndex += sizeof(arp_header);


        if(pcap_sendpacket(handle,buffer,packetIndex) != 0) {
            printf("Send Fail.\n");
        }
    }

    pcap_close(handle);
    return 0;
}