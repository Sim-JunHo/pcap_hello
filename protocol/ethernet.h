#pragma once
#include <stdint.h>

#define ETH_ALEN 6

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_REVARP 0x8035
#define ETHERTYPE_AT 0x809B
#define ETHERTYPE_IPv6 0x86dd
#define ETHERTYPE_LOOPBACK 0x9000
#define MAC_LENGTH 6
#define IPV4_LENGTH 4
struct mac_addr {
	uint8_t oui[3];
	uint8_t nic[3];
};

struct ether_header {
	uint8_t dst[ETH_ALEN];
	uint8_t src[ETH_ALEN];
	uint16_t ether_type;
} __attribute__ ((__packed__));