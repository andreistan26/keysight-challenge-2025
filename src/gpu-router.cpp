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

#include "dpc_common.hpp"

constexpr size_t burst_size = 8;
constexpr size_t packet_size = 1518;

using Packet = std::array<uint8_t, packet_size>;
using PacketBurst = std::array<Packet *, burst_size>;

struct CaptureContext {
    PacketBurst burst;
    std::array<uint32_t, burst_size> packet_lengths;
    size_t count;

    CaptureContext() : count(0) {
        for (size_t i = 0; i < burst_size; ++i) {
            burst[i] = new Packet();
        }
    }
};

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
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file>\n";
        return 1;
    }

    sycl::queue q(sycl::gpu_selector_v, dpc_common::exception_handler);
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

    tbb::flow::function_node<CaptureContext, Counters> inspect_packet_node{
        g,
        tbb::flow::unlimited,
        [&](const CaptureContext &context) -> Counters {
            Counters local_counters;

            if (context.count == 0) {
                return local_counters;
            }

            try {
                std::vector<std::array<uint8_t, packet_size>> host_packets(context.count);
                for (size_t i = 0; i < context.count; i++) {
                    host_packets[i] = *context.burst[i];
                }

                sycl::buffer<std::array<uint8_t, packet_size>> packets_buf(host_packets.data(), context.count);
                sycl::buffer<uint32_t> lengths_buf(context.packet_lengths.data(), context.count);
                sycl::buffer<Counters> counters_buf(&local_counters, 1);

                q.submit([&](sycl::handler &h) {
                    auto packets = packets_buf.get_access<sycl::access::mode::read>(h);
                    auto lengths = lengths_buf.get_access<sycl::access::mode::read>(h);
                    auto counters = counters_buf.get_access<sycl::access::mode::atomic>(h);

                    h.parallel_for(sycl::range<1>(context.count), [=](sycl::id<1> idx) {
                        const auto& packet = packets[idx];
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

    tbb::flow::make_edge(in_node, inspect_packet_node);


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
