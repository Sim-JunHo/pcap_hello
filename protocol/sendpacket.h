#pragma once
#include <stdio.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include "ip.h"
#include "ethernet.h"

int pcap_inject(pcap_t *p, const void *buf, size_t size);
int pcap_sendpacket(pcap_t *p, const u_char *buf, int size);

bool arpSend(pcap_t *handle, mac_addr srcMAC, mac_addr destMAC, uint16_t arpOpcode, ip_addr arpSrcIP, mac_addr arpSrcMAC, ip_addr arpDestIP, mac_addr arpDestMAC);

bool arpRequest(pcap_t *handle, mac_addr srcMAC, mac_addr destMAC, uint16_t arpOpcode);

bool arpReply(pcap_t *handle, ip_addr arpSrcIP, mac_addr arpSrcMAC, ip_addr arpDestIP, mac_addr arpDestMAC)
{
    return arpSend(handle, arpSrcMAC, arpDestMAC, ARPOP_REPLY, arpSrcIP, arpSrcMAC, arpDestIP, arpDestMAC);
}