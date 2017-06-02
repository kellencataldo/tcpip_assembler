#include "connection.h"
#include <iostream>
#include "fileread.h"

std::vector<connection>tcp_connections;
global_struct global_header;


void connection::sort_packets() {
	sorter(this->dataup, this->up_behavior);
	sorter(this->datadown, this->down_behavior);
	this->tcp_teardown = check_close();
	return;
}

void connection::sorter(std::vector<combo>& packets, behavior &behave) {
	std::vector<combo>::iterator i;
	bool swap_occured = true;
	while (swap_occured) {
		swap_occured = false;
		for (i = packets.begin(); i < packets.end() - 1; i++) {
			int location = i - packets.begin();
			if (packets.at(location) > packets.at(location + 1)) {
				swap_occured = true;
				behave.oop++;
				global_header.oop_packets++;
				std::swap(packets.at(location), packets.at(location + 1));

			}
			if (packets.at(location) == packets.at(location + 1)) {
				packets.at(location).dup = true;
				behave.dup++;
			}
			if ((packets.at(location).flags & 4) == 4) {
				behave.reset++;
				global_header.resets++;
			}
		}
	}
}

bool connection::check_close() {
	int end = this->dataup.end() - this->dataup.begin(); 
	bool handshake = ((this->dataup.at(end-2).flags & 1) == 1) || ((this->dataup.at(end - 1).flags & 1) == 1);
	end = this->datadown.end() - this->datadown.begin();
	handshake &= ((this->datadown.at(end - 1).flags & 1) == 1) || ((this->datadown.at(end - 2).flags & 1) == 1);

	if (!handshake) {
		global_header.bad_closes++;
	}
	return handshake;
}

void connection::print_connection() {
	uint8_t sourceip[INET_ADDRSTRLEN];
	uint8_t destip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(this->ip_source), (PSTR)sourceip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(this->ip_dest), (PSTR)destip, INET_ADDRSTRLEN);

	std::cout << "Connection between IP 1: " << sourceip << " on port " << this->sourceport << " and IP 2: ";
    std::cout << destip << " on port " << this->destport << std::endl;

	std::cout << "From IP 1 to IP 2 -> Number of packets: " << this->dataup.size();
	std::cout << ". Size of data in bytes: " << this->up << std::endl;
	std::cout << "Possible duplicate packets: " << this->up_behavior.dup
		<< ". Out of order packets: " << this->up_behavior.oop << ". Reset packets sent: " << this->up_behavior.reset << std::endl;

	std::cout << "From IP 2 to IP 1 -> Number of packets: " << this->datadown.size();
	std::cout << ". Size of data in bytes: " << this->down << std::endl;
	std::cout << "Possible duplicate packets: " << this->down_behavior.dup
		<< ". Out of order packets: " << this->down_behavior.oop << ". Reset packets sent: " << this->down_behavior.reset
		<< std::endl;
	if (this->tcp_teardown) {
		std::cout << "Successful TCP Teardown";
	}
	else {
		std::cout << "Unsuccessful TCP Teardown";
	}
	std::cout << std::endl << std::endl;
}

void connection::print_packets(uint8_t option_flags, std::vector<combo>& packets) {
	std::vector<combo>::iterator i;
	for (i = packets.begin(); i < packets.end(); i++) {
		int location = i - packets.begin();
		if ((option_flags & 8) == 8) {
			std::cout << "RELATIVE SEQUENCE NUMBER: " << location;
			std::cout << ". DATA SIZE IN BYTES: " << packets.at(location).size << ".";

			if (packets.at(location).dup) {
				std::cout << " POSSIBLE TCP RETRANSMISSION.";
			}
			if ((packets.at(location).flags & 4) == 4) {
				std::cout << " CONNECTION RESET FLAG SET.";
			}
			std::cout << std::endl;
		}

		if ((option_flags & 1) == 1) {
			fflush(stdout);
			fwrite(data + packets.at(location).loc, 1, packets.at(location).size, stdout);
			std::cout << std::endl << std::endl;
		} 
	}
	std::cout << std::endl;
}

void connection::process_connection(uint8_t option_flags) {
	if ((option_flags & 16) == 16) {
		print_connection();
	}
	if ((option_flags & 8) == 8) {
		std::cout << "DATA UPLOADED: " << std::endl << std::endl;
	}
	print_packets(option_flags, this->dataup);

	if ((option_flags & 8) == 8) {
		std::cout << "DATA DOWNLOADED: " << std::endl << std::endl;
	}
	print_packets(option_flags, this->datadown);
}

void print_global_header(uint8_t option_flags, uint16_t port, uint32_t ip) {
	std::cout << "Total unique TCP/IP connections: " << global_header.unique_connections;
	std::cout << ". Total bytes transferred across connection(s): " << global_header.total_bytes << std::endl;
	std::cout << "Total unique packets: " << global_header.unique_packets;
	std::cout << ". Out of order packets detected: " << global_header.oop_packets;
	std::cout << ". Possible duplicate packets detected: " << global_header.dup_packets;
	std::cout << ". Reset packets sent or recieved: " << global_header.resets << std::endl;
	std::cout << "Total unsuccessful TCP teardowns: " << global_header.bad_closes << std::endl;
	if ((option_flags & 4) == 4) {
		std::cout << "Filtering for port: " << port << std::endl;
	}
	if ((option_flags & 2) == 2) {
		uint8_t print_ip[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &(ip), (PSTR)print_ip, INET_ADDRSTRLEN);
		std::cout << "Filtering for IP: " << print_ip << std::endl << std::endl;
	}
	std::cout << std::endl;
}

void process_request(uint8_t option_flags, uint16_t port, uint32_t ip) {
	std::vector<connection>::iterator i;
	for (i = tcp_connections.begin(); i < tcp_connections.end(); i++) {
		tcp_connections.at(i - tcp_connections.begin()).sort_packets();
	}

	if ((option_flags & 32) == 32) {
		print_global_header(option_flags, port, ip);
	}

	for (i = tcp_connections.begin(); i < tcp_connections.end(); i++) {
		tcp_connections.at(i - tcp_connections.begin()).process_connection(option_flags);
	}
}