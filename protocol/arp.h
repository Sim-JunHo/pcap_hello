#pragma once
#include <stdint.h>
#include "ip.h"
#include "ethernet.h"

#define APRHEAD_ETHER 1
#define ARPOP_ERQEST 1
#define ARPOP_REPLY 2
#define ARPOP_RREQUEST 3
#define ARPOP_RREPLY 4
#define ARPOP_InREQURST 8
#define ARPOP_InREPLY 9
#define ARPOP_NAK 10

#define ARPPRO_IPV4 0x0800

struct __attribute__((aligned(1), packed)) arp_header {
	uint16_t hardware_type;
	uint16_t protocol_type;
	uint8_t hardware_size;
	uint8_t protocol_size;
	uint16_t opcode;
	
	mac_addr sender_mac;
	ip_addr sender_ip;
	mac_addr target_mac;
	ip_addr target_ip;
};