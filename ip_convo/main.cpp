#include "fileread.h"
#include "connection.h"
#include <string>

uint8_t *data;
int DATASIZE;

int main(int nargs, char * args[]) {
	//global header
	//connection headers
	//packet headers
	//specific port
	//specific ip
	//raw data / no data
	uint8_t option_flags = 57;
	uint16_t port = 0;
	uint32_t ip = 0;
	DATASIZE = 10000000;

	for (int i = 1; i < nargs; i++) {
		//c++ doesnt support string switch cases unfortunatley
		std::string arg = args[i];
		if (arg == "-gh") { option_flags |= 32; }
		if (arg == "-ch") { option_flags |= 16; }
		if (arg == "-ph") { option_flags |= 8; }
		if (arg == "-port" && i < nargs + 1) {
			port = atoi(args[i + 1]);
			option_flags |= 4;
		}
		if (arg == "-ip" && i < nargs + 1) {
			inet_pton(AF_INET, args[i + 1], &ip);
			option_flags |= 2;
		}
		if (arg == "-nd") {
			option_flags |= 1;
		}
		if (arg == "-rs" && i < nargs + 1) {
			DATASIZE = atoi(args[i + 1]) * 1000000;
		}
	}
	
	data = (uint8_t *)malloc(sizeof(uint8_t) * DATASIZE);
	file_read(option_flags, port, ip);
	process_request(option_flags, port, ip);

	free(data);
	return 0;
}