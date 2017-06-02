#include <stdint.h>
#include <vector>

struct  global_struct {
	global_struct() : unique_connections(0), unique_packets(0), total_bytes(0), oop_packets(0), dup_packets(0), resets(0),
	bad_closes(0) {}

	int unique_connections;
	int unique_packets;
	long total_bytes;
	int oop_packets;
	int dup_packets;
	int resets;
	int bad_closes;
};

extern global_struct global_header; 
void process_request(uint8_t option_flags, uint16_t port, uint32_t ip);

//void tcp_sorter();
struct behavior {
	void init_val() {
		this->oop = this->dup = this->reset = 0;
	}
	int oop;
	int dup;
	int reset;
};
struct combo {
	void init_val(uint32_t array_offset, uint32_t seq, uint32_t ack_seq, uint16_t data_size, uint16_t ip_id, uint16_t  flags) {
		this->loc = array_offset;
		this->seq = seq;
		this->ack_seq = ack_seq;
		this->ip_id = ip_id;
		this->flags = flags;
		this->dup = false;
		this->size = data_size;
	}
	bool operator == (const combo &rhs) const
	{
		return ((seq == rhs.seq) && (ack_seq == rhs.ack_seq) && (flags == rhs.flags) && (ip_id != rhs.ip_id) && (size == rhs.size));
	}
	bool operator > (const combo &rhs) const
	{
		return (seq > rhs.seq);
	}
	uint32_t loc;
	uint32_t seq;
	uint32_t ack_seq;
	uint16_t ip_id;
	uint16_t  flags;
	bool dup;
	uint16_t size;
};


class connection {
public:
	bool operator == (const connection &rhs) const
	{
		return ((unique_id == rhs.unique_id) && (unique_port == rhs.unique_port));
	}
	void init_val(uint32_t source_ip, uint32_t dest_ip, uint16_t port_source, uint16_t port_dest) {
		this->ip_source = source_ip;
		this->ip_dest = dest_ip;
		this->sourceport = port_source;
		this->destport = port_dest;
		this->up = this->down = 0;
		this->down_behavior.init_val();
		this->up_behavior.init_val();
	}
	void sort_packets();
	void process_connection(uint8_t option_flags); 
	uint64_t unique_id;
	uint32_t unique_port;
	uint32_t up;
	uint32_t down;
	uint16_t sourceport;
	uint16_t destport;
	behavior up_behavior;
	behavior down_behavior;
	std::vector<combo> dataup;
	std::vector<combo> datadown;
	bool tcp_teardown;
private:
	uint32_t ip_source;
	uint32_t ip_dest;
	void sorter(std::vector<combo>& packets, behavior &behave);
	void print_packets(uint8_t option_flags, std::vector<combo>& packets);
	void print_connection();
	bool check_close();
};

extern std::vector<connection>tcp_connections;

