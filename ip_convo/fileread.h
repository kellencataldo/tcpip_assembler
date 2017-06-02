#pragma comment(lib, "Ws2_32.lib")
#include <stdio.h>
#include <iostream>
#include <Ws2tcpip.h>

#define PACKSIZE 65536

#ifndef IP_PROTOCOL
#define IP_PROTOCOL 0x0800
#endif

#define BYTE_ORDER LITTLE_ENDIAN

extern uint8_t *data;
extern int DATASIZE;
void file_read(uint8_t option_flags, uint16_t port, uint32_t ip);

struct pcap_struct {
	uint32_t magic_number;
	uint16_t version_major;
	uint16_t version_minor;
	int32_t  thiszone;
	uint32_t sigfigs;
	uint32_t snaplen;
	uint32_t network;
};

struct pack_struct {
	uint32_t ts_sec;
	uint32_t ts_usec;
	uint32_t incl_len;
	uint32_t orig_len;
};

struct ether_struct {
	uint8_t dst[6];
	uint8_t src[6];
	uint16_t type;
};

struct ip_struct {
	#if BYTE_ORDER == LITTLE_ENDIAN
		uint8_t ip_hdr_len : 4;   
		uint8_t ip_version : 4;   
	#else
		uint8_t ip_version : 4;   
		uint8_t ip_hdr_len : 4;   
	#endif
	uint8_t ip_tos;
    uint16_t ip_len;
    uint16_t ip_id;
    uint16_t ip_off;
    uint8_t ip_ttl;
    uint8_t ip_proto;
    uint16_t ip_chk;
	uint32_t ip_source;
    uint32_t ip_dest;
};

//there is more to the tcp header but this is unneeded
struct tcp_struct {
	uint16_t tcp_source;
	uint16_t tcp_dest;
	uint32_t seq;
	uint32_t ack_seq;
	uint16_t control_flags;
};

