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
using PacketBurst = std::array<Packet, burst_size>;

struct CaptureContext {
    PacketBurst burst;
    std::array<uint32_t, burst_size> packet_lengths;
    size_t count;

	CaptureContext() : count(0) {}

};

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file>\n";
        return 1;
    }

    sycl::queue q;
    std::cout << "Using device: " << q.get_device().get_info<sycl::info::device::name>() << "\n";

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[1], errbuf);
    if (!handle) {
        std::cerr << "Error opening pcap file: " << errbuf << "\n";
        return 1;
    }

    // TBB setup
    int nth = 10;

	tbb::global_control gc(tbb::global_control::max_allowed_parallelism, nth);
    tbb::flow::graph g;

    // Input node: read bursts from pcap file
    tbb::flow::input_node<CaptureContext> in_node{
        g,
        [&](tbb::flow_control &fc) -> CaptureContext {
			auto context = CaptureContext{};

            while (context.count < burst_size) {
                struct pcap_pkthdr *header;
                const u_char *packet;
                int res = pcap_next_ex(handle, &header, &packet);
				std::cout << "res = " << res << "\n";
                if (res == 1) {
					std::cout << "reading packet " << context.count << "\n";
					if (header->caplen > packet_size) {
						std::cerr << "Packet size exceeds buffer size\n";
						continue;
					}
                    std::copy(packet, packet + header->caplen, context.burst[context.count].begin());
                    context.packet_lengths[context.count] = header->caplen;
                    context.count++;
				} else if (res == -2){
					if (context.count == 0) {
						fc.stop();
						return {};
					} else {
						break;
					}
                } else if (res < 0) {
                    fc.stop();
                    return {};
                }
            }

            return context;
        }};

    // Packet inspection node
    tbb::flow::function_node<CaptureContext, int> inspect_packet_node{
        g,
        tbb::flow::unlimited,
        [&](const CaptureContext context) -> int {
			sycl::queue gpuQ(sycl::gpu_selector_v, dpc_common::exception_handler);

			try {

				gpuQ.submit([&](sycl::handler &h) { 
					//h.parallel_for(sycl::range<1>(context->count), [=](sycl::id<1> idx) {
					//});
				}).wait_and_throw();
			} catch (const sycl::exception &e) {
				std::cerr << "SYCL exception: " << e.what() << "\n";
				return 0;
			}

            std::cout << "Processed burst of " << context.count << " packets:\n";
            for (size_t i = 0; i < context.count; ++i) {
                std::cout << "Packet " << i + 1 << ": Length = " << context.packet_lengths[i] << " bytes\n";
            }

            return static_cast<int>(context.count);
        }};

    // Construct graph
    tbb::flow::make_edge(in_node, inspect_packet_node);

    // Start processing
    in_node.activate();
    g.wait_for_all();

    // Cleanup
    pcap_close(handle);

    return 0;
}
