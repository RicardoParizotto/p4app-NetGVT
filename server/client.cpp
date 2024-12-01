#include <iostream>
#include <thread>
#include <vector>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <iomanip>

#define ETHERTYPE_GVT 0x8666
#define TYPE_PROPOSAL 1
#define TYPE_DELIVER  0

struct GvtProtocol {
    uint8_t type;
    uint32_t value;
    uint32_t pid;
    uint32_t gvt;
} __attribute__((packed));

int gvt = 0;
double start_ppkt = 0;
int pid = 0;
std::vector<double> latencies;

void print_packet(const uint8_t *packet, size_t length) {
    std::cout << "Packet content (" << length << " bytes): ";
    for (size_t i = 0; i < length; ++i) {
        if (i % 16 == 0) std::cout << "\n";
        std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)packet[i] << " ";
    }
    std::cout << std::dec << "\n"; // Resetando para decimal
}

void handle_pkt(const struct pcap_pkthdr *header, const uint8_t *packet) {
    auto end = std::chrono::high_resolution_clock::now();
    double end_time = std::chrono::duration<double>(end.time_since_epoch()).count();

    // Parse GvtProtocol assuming it's right after the Ethernet header (14 bytes)
    const GvtProtocol *gvt_header = reinterpret_cast<const GvtProtocol *>(packet + 14);
    gvt = ntohl(gvt_header->gvt);

    std::cout << "Latency: " << end_time - start_ppkt << " seconds" << std::endl;
    latencies.push_back(1000 * (end_time - start_ppkt)); // Store latency in milliseconds
}

void receive_packets() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("enp1s0np1", BUFSIZ, 1, 1000, errbuf);

    if (!handle) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        exit(EXIT_FAILURE);
    }

    struct bpf_program filter;
    std::string filter_exp = "ether proto 0x8666";
    if (pcap_compile(handle, &filter, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Error compiling filter: " << pcap_geterr(handle) << std::endl;
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &filter) == -1) {
        std::cerr << "Error setting filter: " << pcap_geterr(handle) << std::endl;
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, -1, [](uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *packet) {
        handle_pkt(header, packet);
    }, nullptr);

    pcap_close(handle);
}

void send_packets(const char *src_ip, int end_simulation_loop) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("enp1s0np1", BUFSIZ, 1, 1000, errbuf);

    if (!handle) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        exit(EXIT_FAILURE);
    }

    struct ether_header eth_hdr;
    memset(&eth_hdr, 0, sizeof(eth_hdr));
    eth_hdr.ether_type = htons(ETHERTYPE_GVT);
    memset(eth_hdr.ether_dhost, 0xFF, sizeof(eth_hdr.ether_dhost));

    uint32_t lvt = 0;
    auto start = std::chrono::high_resolution_clock::now();

    while (lvt < end_simulation_loop) {
        if (lvt <= gvt) {
            lvt++;

            GvtProtocol gvt_hdr = {TYPE_PROPOSAL, htonl(lvt), htonl(pid), htonl(gvt)};

            uint8_t packet[sizeof(ether_header) + sizeof(GvtProtocol)];
            memcpy(packet, &eth_hdr, sizeof(ether_header));
            memcpy(packet + sizeof(ether_header), &gvt_hdr, sizeof(GvtProtocol));

            start_ppkt = std::chrono::duration<double>(
                             std::chrono::high_resolution_clock::now().time_since_epoch())
                             .count();

            print_packet(packet, sizeof(packet));

            const struct ether_header *eth_hdr = (struct ether_header *)packet;
            std::cout << "Ethernet Header:" << std::endl;
            std::cout << "  Source MAC: " << ether_ntoa((struct ether_addr *)eth_hdr->ether_shost) << std::endl;
            std::cout << "  Destination MAC: " << ether_ntoa((struct ether_addr *)eth_hdr->ether_dhost) << std::endl;
            std::cout << "  Ethertype: 0x" << std::hex << ntohs(eth_hdr->ether_type) << std::dec << std::endl;

            // Verificar se é nosso protocolo (ETHERTYPE_GVT = 0x8666)
            if (ntohs(eth_hdr->ether_type) == 0x8666) {
                const GvtProtocol *gvt_hdr = (GvtProtocol *)(packet + sizeof(struct ether_header));
                std::cout << "GVT Protocol Header:" << std::endl;
                std::cout << "  Type: " << (int)gvt_hdr->type << std::endl;
                std::cout << "  Value: " << ntohl(gvt_hdr->value) << std::endl;
                std::cout << "  PID: " << ntohl(gvt_hdr->pid) << std::endl;
            } else {
                std::cout << "Packet is not GVT Protocol." << std::endl;
            }

            if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
                std::cerr << "Error sending packet: " << pcap_geterr(handle) << std::endl;
            }
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    double total_time = std::chrono::duration<double>(end - start).count();
    std::cout << "Total time: " << total_time << " seconds" << std::endl;

    pcap_close(handle);
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <source IP> <pid> <size>" << std::endl;
        return EXIT_FAILURE;
    }

    pid = std::stoi(argv[2]);
    int end_simulation_loop = std::stoi(argv[3]);

    std::thread recv_thread(receive_packets);
    std::thread send_thread(send_packets, argv[1], end_simulation_loop);

    recv_thread.join();
    send_thread.join();

    return EXIT_SUCCESS;
}
