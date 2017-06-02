#include "fileread.h"
#include "connection.h"
#include <io.h>
#include <fcntl.h>
#include <algorithm>


#ifdef _WIN32
int OUTPUT_MODE = _setmode(_fileno(stdout), _O_TEXT);
int INPUT_MODE = _setmode(_fileno(stdin), _O_BINARY);
#endif

bool check_valid(uint8_t option_flags, uint16_t port, uint32_t ip, uint16_t source_port, uint16_t dest_port, 
	uint32_t source_ip, uint32_t dest_ip) {
	
	uint8_t case_check = option_flags & 6;
	switch (case_check) {
	case 6:
		return ((port == source_port) || (port == dest_port)) && ((ip == source_ip) || (ip == dest_ip));
	case 4:
		return ((port == source_port) || (port == dest_port));
	case 2:
		return ((ip == source_ip) || (ip == dest_ip));
	case 0:
		return true;
	default:
		return false;
	}
}

void file_read(uint8_t option_flags, uint16_t port, uint32_t ip) {
	//possible change here
	uint8_t headerbuf[24];
	uint8_t packet[PACKSIZE];
	const struct pcap_struct* pcap_header;
	const struct pack_struct* packet_header;
	const struct ether_struct* ethernet_header;
	const struct ip_struct* ip_header;
	const struct tcp_struct* tcp_header;
	int array_offset = 0;

	pcap_header = (struct pcap_struct*)headerbuf;
	fread(headerbuf, 1, 24, stdin);

	while (fread(packet, 1, 16, stdin)) {
		packet_header = (struct pack_struct*)packet;

		fread(packet, 1, packet_header->incl_len, stdin);

		if (packet_header->incl_len < sizeof(ether_struct) + sizeof(ip_struct) + sizeof(ip_struct)) {
			return;
		}

		ethernet_header = (struct ether_struct*)packet;
		ip_header = (struct ip_struct*)(packet + sizeof(struct ether_struct));
		tcp_header = (tcp_struct*)(packet + sizeof(struct ether_struct) + sizeof(struct ip_struct));
		uint16_t dest_port = ntohs(tcp_header->tcp_dest);
		uint16_t source_port = ntohs(tcp_header->tcp_source);
		uint32_t source_ip = ip_header->ip_source;
		uint32_t dest_ip = ip_header->ip_dest;

		if ((ntohs(ethernet_header->type) == IP_PROTOCOL) && (ip_header->ip_proto == IPPROTO_TCP) && 
			check_valid(option_flags, port, ip, dest_port, source_port, source_ip, dest_ip)) {
			global_header.unique_packets++;

			int data_offset = 4 * (ntohs(tcp_header->control_flags) >> 12);
			int data_size = ntohs(ip_header->ip_len) - sizeof(struct ip_struct) - data_offset;
			global_header.total_bytes += data_size;

			auto unique_sum = [=](uint32_t a, uint32_t b) -> uint64_t {
				uint64_t morton_num = 0;
				for (int i = 0; i < 63; i++) {
					morton_num |= (a & 1 << i) << i | (b & 1 << i) << (i + 1);
				}
				return morton_num; };
			uint32_t max = source_ip;
			uint32_t min = dest_ip;
			if (min > max) { max = dest_ip;  min = source_ip; }
			connection convo_tuple;
			convo_tuple.unique_id = unique_sum(max, min);

			max = dest_port;
			min = source_port;
			if (min > max) { max = source_port;  min = dest_port; }
			convo_tuple.unique_port = (uint32_t)unique_sum(max, min);
			ptrdiff_t location = std::find(tcp_connections.begin(), tcp_connections.end(), convo_tuple) - tcp_connections.begin();

			if (location == tcp_connections.size()) {
				convo_tuple.init_val(source_ip, dest_ip, source_port, dest_port);
				tcp_connections.push_back(convo_tuple);
				global_header.unique_connections++;
			}

			uint8_t * d = data + array_offset;
			uint8_t * s = packet + sizeof(struct ether_struct) + sizeof(struct ip_struct) + data_offset;
			memcpy(d, s, data_size);

			combo new_packet;
			new_packet.init_val(array_offset, ntohl(tcp_header->seq), ntohl(tcp_header->ack_seq),
				data_size, ntohs(ip_header->ip_id), (ntohs(tcp_header->control_flags) & 63));

			if (tcp_connections.at(location).sourceport == source_port) {
				tcp_connections.at(location).up += data_size;
				tcp_connections.at(location).dataup.push_back(new_packet);
			}
			else {
				tcp_connections.at(location).down += data_size;
				tcp_connections.at(location).datadown.push_back(new_packet);
			}

			try {
				array_offset += data_size;
				if (array_offset > DATASIZE) { throw array_offset - DATASIZE; }
			}
			catch (int x) {
				std::cout << "Data is larger than array size by atleast this amount: " << x;
				std::cout << ". Please increase DATASIZE value\n";
				exit(1);
			}
		}
	}
}
