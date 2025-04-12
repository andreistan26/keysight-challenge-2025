#include <array>
#include <vector>
#include <iostream>
#include <string>
#include <stdexcept>
#include <memory>

#include <sycl/sycl.hpp>
#include <tbb/blocked_range.h>
#include <tbb/global_control.h>
#include <tbb/flow_graph.h>
#include <pcap.h>

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "dpc_common.hpp"

#define IS_TYPE(x, y) ((x) & (1 << (y)))

#define UNKNOWN 0
#define IPV4 1
#define IPV6 2
#define TCP 3
#define UDP 4
#define ICMP 5
#define ARP 6

constexpr size_t burst_size = 8;
constexpr size_t packet_size = 1518;
char *output_interface_name = NULL;
char *input_interface_name = NULL;

using Packet = std::array<uint8_t, packet_size>;
using PacketBurst = std::array<Packet *, burst_size>;
using PacketTypes = std::array<uint8_t, burst_size>;

bool receive_one_packet(const char* interface_name, Packet *out_packet, uint32_t& packet_length) {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket");
        return false;
    }

    // Get interface index
    struct ifreq ifr;
    std::strncpy(ifr.ifr_name, interface_name, IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        close(sockfd);
        return false;
    }

    // Bind socket to interface
    struct sockaddr_ll saddr = {};
    saddr.sll_family   = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_ALL);
    saddr.sll_ifindex  = ifr.ifr_ifindex;

    if (bind(sockfd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0) {
        perror("bind");
        close(sockfd);
        return false;
    }

    // Receive a single packet
    uint8_t buffer[packet_size];
    ssize_t len = recv(sockfd, buffer, sizeof(buffer), 0);
    if (len < 0) {
        perror("recv");
        close(sockfd);
        return false;
    }

    // Copy into Packet
    std::copy(buffer, buffer + len, out_packet->begin());
    packet_length = len;

    close(sockfd);
    return true;
}

uint16_t calculate_checksum(const uint8_t* data, size_t length) {
    uint32_t sum = 0;

    // Sum every 16-bit word
    for (size_t i = 0; i < length; i += 2) {
        uint16_t word = data[i] << 8;
        if (i + 1 < length) {
            word |= data[i + 1];
        }
        sum += word;
    }

    // Fold overflow
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return static_cast<uint16_t>(~sum);
}

void recalculate_ipv4_checksum(Packet* packet) {
    constexpr size_t ethernet_header_length = 14;
    constexpr size_t ipv4_header_offset = ethernet_header_length;

    // Extract the IPv4 header length (IHL) from the packet (in 32-bit words)
    uint8_t ihl = (*packet)[ipv4_header_offset] & 0x0F;
    size_t ipv4_header_length = ihl * 4;

    // Zero out the checksum field before recalculating
    size_t checksum_offset = ipv4_header_offset + 10;
    (*packet)[checksum_offset] = 0;
    (*packet)[checksum_offset + 1] = 0;

    // Calculate the checksum
    uint16_t checksum = calculate_checksum(packet->data() + ipv4_header_offset, ipv4_header_length);

    // Write checksum back into the header (big-endian / network byte order)
    (*packet)[checksum_offset] = checksum >> 8;
    (*packet)[checksum_offset + 1] = checksum & 0xFF;
}

void decrement_ttl(Packet *packet) {
    constexpr size_t ethernet_header_length = 14;
    constexpr size_t ipv4_header_offset = ethernet_header_length;
    constexpr size_t ttl_offset = ipv4_header_offset + 8;

    // Decrement TTL (don't let it wrap below 0)
    if ((*packet)[ttl_offset] > 0) {
        --(*packet)[ttl_offset];
    }

    // Recalculate checksum after modifying TTL
    recalculate_ipv4_checksum(packet);
}

void send_raw_packet(const char* interface, const uint8_t* data, size_t data_len) {
    // Create raw socket for Ethernet frames
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("Socket creation failed");
        return;
    }

    // Get interface index
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("Unable to get interface index");
        close(sock);
        return;
    }

    // Bind socket to interface
    struct sockaddr_ll socket_address;
    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_ifindex = ifr.ifr_ifindex;
    socket_address.sll_halen = ETH_ALEN;
    // Copy destination MAC from Ethernet header in data
    memcpy(socket_address.sll_addr, data, ETH_ALEN);

    if (bind(sock, (struct sockaddr*)&socket_address, sizeof(socket_address)) < 0) {
        perror("Bind failed");
        close(sock);
        return;
    }

    // Send the packet
    if (sendto(sock, data, data_len, 0, (struct sockaddr*)&socket_address, sizeof(socket_address)) < 0) {
        perror("Send failed");
    }

    close(sock);
}

struct IPv4Header {
    uint8_t  version_ihl;     // Versioncal (4 bits) + IHL (4 bits)
    uint8_t  tos;             // Type of Service
    uint16_t total_length;    // Total length (16 bits)
    uint16_t identification;  // Identification (16 bits)
    uint16_t flags_offset;    // Flags (3 bits) + Fragment offset (13 bits)
    uint8_t  ttl;             // Time to live
    uint8_t  protocol;        // Protocol (e.g., TCP = 6, UDP = 17)
    uint16_t checksum;        // Checksum (16 bits)
    uint32_t source_ip;       // Source IP address (32 bits)
    uint32_t dest_ip;         // Destination IP address (32 bits)

    // Simplified function to return pointer to the raw header data
    uint8_t* data() {
        return reinterpret_cast<uint8_t*>(this);
    }
};

struct CaptureContext {
	PacketTypes types;
    PacketBurst burst;
    std::array<uint32_t, burst_size> packet_lengths;
    size_t count;


    CaptureContext() : count(0) {
		std::fill(types.begin(), types.end(), UNKNOWN);
        for (size_t i = 0; i < burst_size; ++i) {
            burst[i] = new Packet();
        }
    }

	void push_back(Packet *packet) {
		if (count < burst_size) {
			burst[count] = packet;
			count++;
		}
	}

	size_t size() const {
		return count;
	}
};

uint16_t calculate_ipv4_checksum(IPv4Header *header) {
    uint16_t* data = reinterpret_cast<uint16_t*>(header);
    uint32_t sum = 0;
    
    // Set the checksum field to 0 before calculation
    header->checksum = 0;
    
    // Sum all 16-bit words in the IPv4 header
    for (size_t i = 0; i < sizeof(IPv4Header) / 2; ++i) {
        sum += data[i];
        
        // Carry around the overflow (16-bit sum wraparound)
        if (sum > 0xFFFF) {
            sum -= 0xFFFF;
        }
    }

    // Take one's complement of the sum
    return static_cast<uint16_t>(~sum);
}

struct Counters {
    uint32_t ipv4_count = 0;
    uint32_t ipv6_count = 0;
    uint32_t tcp_count = 0;
    uint32_t udp_count = 0;
    uint32_t icmp_count = 0;
    uint32_t arp_count = 0;

    Counters() = default;

    Counters &operator+=(const Counters &other) {
        ipv4_count += other.ipv4_count;
        ipv6_count += other.ipv6_count;
        tcp_count += other.tcp_count;
        udp_count += other.udp_count;
        icmp_count += other.icmp_count;
        arp_count += other.arp_count;
        return *this;
    }
};

int main(int argc, char *argv[]) {
    if (argc != 3 && argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file> <output_interface_name> [input_interface_name]\n";
        return 1;
    }
    
    output_interface_name = argv[2];
    
    if (argc == 4) {
        input_interface_name = argv[3];
    }

    sycl::queue q(sycl::cpu_selector_v, dpc_common::exception_handler);
    std::cout << "Using device: " << q.get_device().get_info<sycl::info::device::name>() << "\n";

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[1], errbuf);
    if (!handle) {
        std::cerr << "Error opening pcap file: " << errbuf << "\n";
        return 1;
    }

    Counters global_counters;
    int nth = 10;
    tbb::global_control gc(tbb::global_control::max_allowed_parallelism, nth);
    tbb::flow::graph g;

    tbb::flow::input_node<CaptureContext> in_node{
        g,
        [&](tbb::flow_control &fc) -> CaptureContext {
            CaptureContext context;

            while (context.count < burst_size) {
                struct pcap_pkthdr *header;
                const u_char *packet;
                bool ok = false;
                
                if (input_interface_name == NULL) {
                    int res = pcap_next_ex(handle, &header, &packet);
                    if (res == 1) {
                        if (header->caplen > packet_size) {
                            std::cerr << "Packet size exceeds buffer size\n";
                            continue;
                        }
                        std::copy(packet, packet + header->caplen, context.burst[context.count]->begin());
                        context.packet_lengths[context.count] = header->caplen;
                        context.count++;
                    } else if (res == -2) {
                        if (context.count == 0) {
                            fc.stop();
                            return {};
                        } else {
                            break;
                        }
                    } else if (res < 0) {
                        std::cerr << "Error reading packet: " << pcap_geterr(handle) << "\n";
                        fc.stop();
                        return {};
                    }
                } else {
                    bool status = receive_one_packet(input_interface_name, context.burst[context.count], context.packet_lengths[context.count]);
                    
                    if (status) {
                        context.count++;
                    } else {
                        fc.stop();
                    }
                }
            }

            return context;
        }};

	tbb::flow::function_node<CaptureContext, CaptureContext> parse_packet_node {
		g,
		tbb::flow::unlimited,
		[&](const CaptureContext &context) -> CaptureContext {
			if (context.count == 0) {
				return context;
			}
			
			CaptureContext new_context = context;

            try {
				sycl::queue q(sycl::cpu_selector_v, dpc_common::exception_handler);
                sycl::buffer<Packet *> packets_buf(new_context.burst.data(), new_context.count);
                sycl::buffer<uint32_t> lengths_buf(new_context.packet_lengths.data(), new_context.count);
				sycl::buffer<uint8_t> types_buf(new_context.types.data(), new_context.count);

                q.submit([&](sycl::handler &h) {
                    auto packets = packets_buf.get_access<sycl::access::mode::read>(h);
                    auto lengths = lengths_buf.get_access<sycl::access::mode::read>(h);
					auto types = types_buf.get_access<sycl::access::mode::read_write>(h);

                    h.parallel_for(sycl::range<1>(new_context.count), [=](sycl::id<1> idx) {
                        uint8_t *packet = packets[idx]->data();
                        uint32_t length = lengths[idx];
                        
                        if (length >= 14) {
                            uint16_t ether_type = (packet[12] << 8) | packet[13];
                            
                            if (ether_type == 0x0806) {
								types[idx] |= (1 << ARP);
                            }

                            else if (ether_type == 0x0800) {
                                types[idx] |= (1 << IPV4);

                                if (length >= 34) {
                                    uint8_t protocol = packet[23];
                                    
                                    if (protocol == 6) {
										types[idx] |= (1 << TCP);
                                    }
                                    else if (protocol == 17) {
										types[idx] |= (1 << UDP);
                                    }
                                    else if (protocol == 1) {
										types[idx] |= (1 << ICMP);
                                    }
                                }
                            }
                            else if (ether_type == 0x86DD) {
								types[idx] |= (1 << IPV6);
								
								if (length >= 54) {
                                    uint8_t protocol = packet[20]; // IPv6 Next Header field
                                    
                                    if (protocol == 6) {  // TCP
                                        types[idx] |= (1 << TCP);
                                    }
                                    else if (protocol == 17) {  // UDP
                                        types[idx] |= (1 << UDP);
                                    }
                                }
                            }
                        }
                    });
                }).wait_and_throw();
            } catch (const sycl::exception &e) {
                std::cerr << "SYCL exception: " << e.what() << "\n";
				return new_context;
            }

			return new_context;
		}
	} ;

    tbb::flow::function_node<CaptureContext, Counters> calculate_stats_node{
        g,
        tbb::flow::unlimited,
        [&](const CaptureContext context) -> Counters {
            Counters local_counters;

            if (context.count == 0) {
                return local_counters;
            }

            try {
                sycl::buffer<uint8_t> types_buf(context.types.data(), context.count);
                sycl::buffer<uint32_t> lengths_buf(context.packet_lengths.data(), context.count);
                sycl::buffer<Counters> counters_buf(&global_counters, 1);

                q.submit([&](sycl::handler &h) {
                    auto types = types_buf.get_access<sycl::access::mode::read>(h);
                    auto lengths = lengths_buf.get_access<sycl::access::mode::read>(h);
                    auto counters = counters_buf.get_access<sycl::access::mode::atomic>(h);

                    h.parallel_for(sycl::range<1>(context.count), [=](sycl::id<1> idx) {
                        if (IS_TYPE(types[idx], IPV4)) {
                            auto ipv4_counter = sycl::atomic_ref<uint32_t, sycl::memory_order::relaxed, 
                                sycl::memory_scope::device>(
                                counters.get_pointer()[0].ipv4_count);
                            ipv4_counter.fetch_add(1);
                        }
						if (IS_TYPE(types[idx], IPV6)) {
                            auto ipv6_counter = sycl::atomic_ref<uint32_t, sycl::memory_order::relaxed, 
                                                sycl::memory_scope::device>(
                                                counters.get_pointer()[0].ipv6_count);
                            ipv6_counter.fetch_add(1);            
                        }
						if (IS_TYPE(types[idx], TCP)) {
                            auto tcp_counter = sycl::atomic_ref<uint32_t, sycl::memory_order::relaxed, 
                                               sycl::memory_scope::device>(
                                               counters.get_pointer()[0].tcp_count);
                            tcp_counter.fetch_add(1);
                        }
						if (IS_TYPE(types[idx], UDP)) {
                            auto udp_counter = sycl::atomic_ref<uint32_t, sycl::memory_order::relaxed, 
                               sycl::memory_scope::device>(
                               counters.get_pointer()[0].udp_count);
                            udp_counter.fetch_add(1);
                        }
						if (IS_TYPE(types[idx], ICMP)) {
                            auto icmp_counter = sycl::atomic_ref<uint32_t, sycl::memory_order::relaxed, 
                                sycl::memory_scope::device>(
                                counters.get_pointer()[0].icmp_count);
                            icmp_counter.fetch_add(1);
                        }
                    });
                }).wait_and_throw();
            } catch (const sycl::exception &e) {
                std::cerr << "SYCL exception: " << e.what() << "\n";
                return global_counters;
            }

            return global_counters;
        }};
        
    tbb::flow::function_node<CaptureContext, CaptureContext> ipv4_node {
        g,
        tbb::flow::unlimited,
        [&](const CaptureContext context) -> CaptureContext {
            CaptureContext new_context = context;
            
            sycl::buffer<Packet *> burst_buf(new_context.burst.data(), new_context.count);
            sycl::buffer<uint32_t> len_buf(new_context.packet_lengths.data(), new_context.count);
            sycl::buffer<uint8_t> types_buf(new_context.types.data(), new_context.count);
            
			sycl::queue gpuQ(sycl::cpu_selector_v, dpc_common::exception_handler);
			
			try {
				gpuQ.submit([&](sycl::handler &h) { 
				    auto acc = burst_buf.get_access<sycl::access::mode::read_write>(h);
                    auto len_acc = len_buf.get_access<sycl::access::mode::read_write>(h);
                    auto types_acc = types_buf.get_access<sycl::access::mode::read_write>(h);

					h.parallel_for(sycl::range<1>(new_context.count), [=](sycl::id<1> idx) {
					    if (IS_TYPE(types_acc[idx], IPV4)) {
			                Packet* pkt = acc[idx];
                            uint8_t* data = pkt->data();

                            constexpr int dest_ip_offset = 30;

                            for (int j = 0; j < 4; ++j) {
                                data[dest_ip_offset + j] += 1;
                            }
                            
                            recalculate_ipv4_checksum(pkt);
                            decrement_ttl(pkt);
                        }
					});
				}).wait_and_throw();
			} catch (const sycl::exception &e) {
				std::cerr << "SYCL exception: " << e.what() << "\n";
				return {};
			}

            return new_context;
        }};
                
    tbb::flow::function_node<CaptureContext, int> send_node {
        g,
        tbb::flow::unlimited,
        [&](const CaptureContext &context) -> int {
            for (int i = 0; i < context.count; i++) {
                if (IS_TYPE(context.types[i], IPV4)) {
                    send_raw_packet(output_interface_name, context.burst[i]->data(), context.packet_lengths[i]);
                }
            }
            
            return 0;
        }
    };
    
    tbb::flow::function_node<CaptureContext, CaptureContext> ipv6_node {
        g,
        tbb::flow::unlimited,
        [&](const CaptureContext context) -> CaptureContext {
            CaptureContext new_context = context;
            
            sycl::buffer<Packet *> burst_buf(new_context.burst.data(), new_context.count);
            sycl::buffer<uint32_t> len_buf(new_context.packet_lengths.data(), new_context.count);
            sycl::buffer<uint8_t> types_buf(new_context.types.data(), new_context.count);
            
			sycl::queue gpuQ(sycl::cpu_selector_v, dpc_common::exception_handler);
			
			try {
				gpuQ.submit([&](sycl::handler &h) { 
				    auto acc = burst_buf.get_access<sycl::access::mode::read_write>(h);
                    auto len_acc = len_buf.get_access<sycl::access::mode::read_write>(h);
                    auto types_acc = types_buf.get_access<sycl::access::mode::read_write>(h);

					h.parallel_for(sycl::range<1>(new_context.count), [=](sycl::id<1> idx) {
					    if (IS_TYPE(types_acc[idx], IPV6)) {
			                // ROUTE IPv6 PACKET
                        }
					});
				}).wait_and_throw();
			} catch (const sycl::exception &e) {
				std::cerr << "SYCL exception: " << e.what() << "\n";
				return {};
			}

            return new_context;
        }};

    tbb::flow::make_edge(in_node, parse_packet_node);
    tbb::flow::make_edge(parse_packet_node, calculate_stats_node);
    tbb::flow::make_edge(parse_packet_node, ipv4_node);
    tbb::flow::make_edge(parse_packet_node, ipv6_node);
    tbb::flow::make_edge(ipv4_node, send_node);

    in_node.activate();
    g.wait_for_all();

    std::cout << "IPv4 packets: " << global_counters.ipv4_count << "\n";
    std::cout << "IPv6 packets: " << global_counters.ipv6_count << "\n";
    std::cout << "TCP packets: " << global_counters.tcp_count << "\n";
    std::cout << "UDP packets: " << global_counters.udp_count << "\n";
    std::cout << "ICMP packets: " << global_counters.icmp_count << "\n";
    std::cout << "ARP packets: " << global_counters.arp_count << "\n";

    pcap_close(handle);

    return 0;
}
