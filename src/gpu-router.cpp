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

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include "dpc_common.hpp"

constexpr size_t burst_size = 8;
constexpr size_t packet_size = 1518;
char *output_interface_name = NULL;

enum Types {
	UNKNOWN = 0,
	IPV4,
	IPV6,
	TCP,
	UDP,
	ICMP,
	ARP
};

using Packet = std::array<uint8_t, packet_size>;
using PacketBurst = std::array<Packet *, burst_size>;
using PacketTypes = std::array<Types, burst_size>;

void send_raw_packet(const char* interface, const uint8_t* data, size_t data_len) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) {
        perror("Socket creation failed");
        return;
    }

    // Set the interface for sending the packet
    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("Unable to get interface index");
        close(sock);
        return;
    }
    
    setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ifr.ifr_name, IFNAMSIZ);

    // Send the packet
    if (sendto(sock, data, data_len, 0, nullptr, 0) < 0) {
        perror("Send failed");
    } else {
        std::cout << "Packet sent successfully on interface " << interface << "\n";
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

void print_ip(Packet packet) {
    for (int i = 0; i < 4; i++) {
        std::cout << static_cast<int>(packet[30 + i]) << ".";
    }
    
    std::cout << "\n";
}

uint16_t calculate_ipv4_checksum(IPv4Header *header) {
    uint16_t* data = reinterpret_cast<uint16_t*>(header);
    uint32_t sum = 0;
    
    // Set the checksum field to 0 before calculation
    header.checksum = 0;
    
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
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file> <output_interface_name>\n";
        return 1;
    }
    
    output_interface_name = argv[2];

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

            try {
				sycl::queue q(sycl::gpu_selector_v, dpc_common::exception_handler);
                sycl::buffer<Packet *> packets_buf(context.burst.data(), context.count);
                sycl::buffer<uint32_t> lengths_buf(context.packet_lengths.data(), context.count);
				sycl::buffer<Types> types_buf(context.types.data(), context.count);

                q.submit([&](sycl::handler &h) {
                    auto packets = packets_buf.get_access<sycl::access::mode::read>(h);
                    auto lengths = lengths_buf.get_access<sycl::access::mode::read>(h);
					auto types = types_buf.get_access<sycl::access::mode::read_write>(h);

                    h.parallel_for(sycl::range<1>(context.count), [=](sycl::id<1> idx) {
                        uint8_t *packet = packets[idx]->data();
                        uint32_t length = lengths[idx];
                        
                        if (length >= 14) {
                            uint16_t ether_type = (packet[12] << 8) | packet[13];
                            
                            if (ether_type == 0x0806) {
								types[idx] = ARP;
                            }

                            else if (ether_type == 0x0800) {
                                types[idx] = IPV4;

                                if (length >= 34) {
                                    uint8_t protocol = packet[23];
                                    
                                    if (protocol == 6) {
										types[idx] = TCP;
                                    }
                                    else if (protocol == 17) {
										types[idx] = UDP;
                                    }
                                    else if (protocol == 1) {
										types[idx] = ICMP;
                                    }
                                }
                            }
                            else if (ether_type == 0x86DD) {
								types[idx] = IPV6;
                            }
                        }
                    });
                }).wait_and_throw();
            } catch (const sycl::exception &e) {
                std::cerr << "SYCL exception: " << e.what() << "\n";
				return context;
            }

			for (int i = 0; i < context.count; i++) {
				switch (context.types[i]) {
					case IPV4:
						std::cout << "IPv4 packet\n";
						break;
					case IPV6:
						std::cout << "IPv6 packet\n";
						break;
					case TCP:
						std::cout << "TCP packet\n";
						break;
					case UDP:
						std::cout << "UDP packet\n";
						break;
					case ICMP:
						std::cout << "ICMP packet\n";
						break;
					case ARP:
						std::cout << "ARP packet\n";
						break;
					default:
						std::cout << "Unknown packet type\n";
				}
			}

			return context;
		}
	} ;
/*
    tbb::flow::function_node<ParsedPackets, Counters> calculate_stats_node{
        g,
        tbb::flow::unlimited,
        [&](const ParsedPackets &context) -> Counters {
            Counters local_counters;

            if (context.count == 0) {
                return local_counters;
            }

            try {
                sycl::buffer<Packet *> packets_buf(context.burst.data(), context.count);
                sycl::buffer<uint32_t> lengths_buf(context.packet_lengths.data(), context.count);
                sycl::buffer<Counters> counters_buf(&local_counters, 1);

                q.submit([&](sycl::handler &h) {
                    auto packets = packets_buf.get_access<sycl::access::mode::read>(h);
                    auto lengths = lengths_buf.get_access<sycl::access::mode::read>(h);
                    auto counters = counters_buf.get_access<sycl::access::mode::atomic>(h);

                    h.parallel_for(sycl::range<1>(context.count), [=](sycl::id<1> idx) {
                        uint8_t *packet = packets[idx]->data();
                        uint32_t length = lengths[idx];
                        
                        if (length >= 14) {
                            uint16_t ether_type = (packet[12] << 8) | packet[13];
                            
                            if (ether_type == 0x0806) {
                                auto arp_counter = sycl::atomic_ref<uint32_t, sycl::memory_order::relaxed, 
                                                   sycl::memory_scope::device>(
                                                   counters.get_pointer()[0].arp_count);
                                arp_counter.fetch_add(1);
                            }

                            else if (ether_type == 0x0800) {
                                auto ipv4_counter = sycl::atomic_ref<uint32_t, sycl::memory_order::relaxed, 
                                                    sycl::memory_scope::device>(
                                                    counters.get_pointer()[0].ipv4_count);
                                ipv4_counter.fetch_add(1);
                                
                                if (length >= 34) {
                                    uint8_t protocol = packet[23];
                                    
                                    if (protocol == 6) {
                                        auto tcp_counter = sycl::atomic_ref<uint32_t, sycl::memory_order::relaxed, 
                                                           sycl::memory_scope::device>(
                                                           counters.get_pointer()[0].tcp_count);
                                        tcp_counter.fetch_add(1);
                                    }
                                    else if (protocol == 17) {
                                        auto udp_counter = sycl::atomic_ref<uint32_t, sycl::memory_order::relaxed, 
                                                           sycl::memory_scope::device>(
                                                           counters.get_pointer()[0].udp_count);
                                        udp_counter.fetch_add(1);
                                    }
                                    else if (protocol == 1) {
                                        auto icmp_counter = sycl::atomic_ref<uint32_t, sycl::memory_order::relaxed, 
                                                            sycl::memory_scope::device>(
                                                            counters.get_pointer()[0].icmp_count);
                                        icmp_counter.fetch_add(1);
                                    }
                                }
                            }
                            else if (ether_type == 0x86DD) {
                                auto ipv6_counter = sycl::atomic_ref<uint32_t, sycl::memory_order::relaxed, 
                                                    sycl::memory_scope::device>(
                                                    counters.get_pointer()[0].ipv6_count);
                                ipv6_counter.fetch_add(1);
                            }
                        }
                    });
                }).wait_and_throw();
            } catch (const sycl::exception &e) {
                std::cerr << "SYCL exception: " << e.what() << "\n";
                return local_counters;
            }

            global_counters += local_counters;
            return local_counters;
        }};
        */
    tbb::flow::function_node<CaptureContext, CaptureContext> ipv4_node {
        g,
        tbb::flow::unlimited,
        [&](const CaptureContext context) -> CaptureContext {
            sycl::buffer<Packet *> burst_buf(context.burst.data(), context.count);
            sycl::buffer<uint32_t> len_buf(context.packet_lengths.data(), context.count);
            
			sycl::queue gpuQ(sycl::cpu_selector_v, dpc_common::exception_handler);
			
            for (int i = 0; i < context.count; i++) {
                print_ip(*(context.burst[i]));
            }
			
			try {
				gpuQ.submit([&](sycl::handler &h) { 
				    auto acc = burst_buf.get_access<sycl::access::mode::read_write>(h);
                    auto len_acc = len_buf.get_access<sycl::access::mode::read_write>(h);

					h.parallel_for(sycl::range<1>(context.count), [=](sycl::id<1> idx) {
			            Packet* pkt = acc[idx];
                        uint8_t* data = pkt->data();

                        constexpr int dest_ip_offset = 30;

                        for (int j = 0; j < 4; ++j) {
                            data[dest_ip_offset + j] += 1;
                        }
					});
				}).wait_and_throw();
			} catch (const sycl::exception &e) {
				std::cerr << "SYCL exception: " << e.what() << "\n";
				return {};
			}
			
		    for (int i = 0; i < context.count; i++) {
                print_ip(*(context.burst[i]));
            }

            return context;
        }};
        
        
    tbb::flow::function_node<CaptureContext, int> send_node {
        g,
        tbb::flow::unlimited,
        [&](const CaptureContext context) -> int {
            for (int i = 0; i < context.count; i++) {
                send_raw_packet(output_interface_name, context.burst[i]->data(), context.packet_lengths[i]);
            }
            
            return 0;
        }
    };

    tbb::flow::make_edge(in_node, parse_packet_node);


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
