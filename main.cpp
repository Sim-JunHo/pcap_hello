/*#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include "protocol/all.h"

#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define printline printf("========================================================================================================\n");

const char *HTTP_METHOD_HTTP = "HTTP";
const char *HTTP_METHOD_GET = "GET";
const char *HTTP_METHOD_POST = "POST";
const char *HTTP_METHOD_PUT = "PUT";
const char *HTTP_METHOD_DELETE = "DELETE";
const char *HTTP_METHOD_CONNECT = "CONNECT";
const char *HTTP_METHOD_OPTIONS = "OPTIONS";
const char *HTTP_METHOD_TRACE = "TRACE";
const char *HTTP_METHOD_PATCH = "PATCH";

void *HTTP_METHOD[] = {
	(void *)HTTP_METHOD_HTTP,
	(void *)HTTP_METHOD_GET,
	(void *)HTTP_METHOD_POST,
	(void *)HTTP_METHOD_PUT,
	(void *)HTTP_METHOD_DELETE,
	(void *)HTTP_METHOD_CONNECT,
	(void *)HTTP_METHOD_OPTIONS,
	(void *)HTTP_METHOD_TRACE,
	(void *)HTTP_METHOD_PATCH,

};

bool HTTPmethod(const uint8_t *data, const char *httpmethod, uint32_t size)
{
	int methodsize = strlen(httpmethod);
	if (size < methodsize)
	{
		return false;
	}
	return memcmp(data, httpmethod, methodsize) == 0; //strncmp
}

bool isHTTPprotocol(const uint8_t *p, uint32_t size)
{
	for (int i = 0; i < (sizeof(HTTP_METHOD) / sizeof(void *)); i++)
	{
		bool isfind = HTTPmethod(p, (const char *)HTTP_METHOD[i], size);
		if (isfind)
		{
			return isfind;
		}
	}
	return false;
}

void usage()
{
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

int main(int argc, char *argv[])
{
	clock_t start, now;

	srand((unsigned int)time(NULL));

	if (argc != 2)
	{
		usage();
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

	start = clock();
	while (true)
	{
		struct pcap_pkthdr *header;
		const u_char *packet;
		int res = pcap_next_ex(handle, &header, &packet);
		int packindex = 0;
		now = clock();

		if (res == 0)
			continue;
		if (res == -1 || res == -2)
			break;

		const ether_header *eth = (ether_header *)packet;
		//MAC 주소 받아오는 코드.
		packindex += sizeof(ether_header);
		const ip_header *ip = (ip_header *)(packet + packindex);
		//IP 주소 받아오는 코드.
		packindex += sizeof(ip_header);

		//if(ntohs(eth->ether_type) != ETHERTYPE_ARP) continue;

		printf("%u bytes captured\n", header->caplen);
		//SRC MAC
		printf("MAC SRC : ");
		for (int i = 0; i < 6; i++)
		{
			printf("%02X", eth->src[i]);
			if (i != 5)
				printf(":");
		}

		//DEST MAC
		printf("\nMAC DEST : ");
		for (int i = 0; i < 6; i++)
		{
			printf("%02X", eth->dst[i]);
			if (i != 5)
				printf(":");
		}

		puts("");

		if (ntohs(eth->ether_type) == ETHERTYPE_IP)
		{
			printf("TYPE : IPv4");

			//SRC IP
			printf("\nIP SRC : ");
			printf("%u.%u.%u.%u", ip->ip_src.a, ip->ip_src.b, ip->ip_src.c, ip->ip_src.d);

			//DEST IP
			printf("\nIP DEST : ");
			printf("%u.%u.%u.%u", ip->ip_dst.a, ip->ip_dst.b, ip->ip_dst.c, ip->ip_dst.d);

			if (ip->ip_p == IPPROTO_TCP)
			{
				const tcp_header *tcp = (tcp_header *)(packet + packindex);
				//TCP 포트 받아오는 코드
				packindex += sizeof(tcp_header);
				//TCP PORT
				printf("\nTCP SRC PORT : %d\n", ntohs(tcp->th_sport));
				printf("TCP DEST PORT : %d\n", ntohs(tcp->th_dport));
				uint32_t tcp_size = (ntohs(ip->ip_len) - ((ip->ip_hl + tcp->th_off) * 4));
				if (tcp_size > 0)
				{
					if (isHTTPprotocol(packet + packindex, tcp_size))
					{
						printline
							printf("%s\n", packet + packindex);
						printline
							printpack(packet + packindex, tcp_size);
						printline
					}
				}
			}

			else if (ip->ip_p == IPPROTO_UDP)
			{
				const udp_header *udp = (udp_header *)(packet + packindex);
				//UDP 포트 받아오는 코드
				packindex += sizeof(udp_header);
				//UDP PORT
				printf("\n\t\tUDP SRC PORT : %d\n", ntohs(udp->uh_sport));
				printf("\t\tUDP DEST PORT : %d\n", ntohs(udp->uh_dport));
				uint32_t udp_size = (ntohs(ip->ip_len) - (ip->ip_hl + udp->uh_off));
				if (udp_size > 0)
				{
					printline
						printpack(packet + packindex, udp_size);
					printline
				}
			}
			else if (ip->ip_p == IPPROTO_ICMP)
			{
				const icmp_header *icmp = (icmp_header *)(packet + packindex);
				packindex += sizeof(icmp_header);
				printf("\nICMP TYPE : %d", icmp->icmp_type);
				printf("\nICMP CODE : %d", icmp->icmp_code);
				printf("\nICMP CHECKSUM : %u\n", ntohs(icmp->icmp_chksum));
				uint16_t icmp_size = (ntohs(ip->ip_len) - (ip->ip_hl + packindex + sizeof(icmp_header)));
				printline
					printpack(packet + packindex, icmp_size);
				printline
			}
		}

		else if (ntohs(eth->ether_type) == ETHERTYPE_ARP)
		{
			printf("\t\t\tTYPE : ARP\n");

			//printpack(packet, header->caplen);

			const arp_header *arp = (arp_header *)packet;
			packindex += sizeof(arp_header);

			uint16_t arp_size = (ntohs(ip->ip_len) - (ip->ip_hl + arp->hardware_size + arp->protocol_size));
			if (arp_size > 0)
			{
				printline
					printpack(packet + packindex, arp_size);
				printline
			}
		}

		//time start~/ms
		printf("\nTIME : %08.3fms\n\n", (double)now - start);
	}
	/*char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "couldn't open device %s : %s", dev, errbuf);
		return -1;
	}
	*
	pcap_close(handle);
	return 0;
}*/