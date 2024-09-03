#define HAVE_REMOTE
#include <pcap.h>
#include <iostream>
#include <cstring>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <unordered_map>
#include <vector>
#include <chrono>

// Define the structures that are not available in Windows headers
struct ip {
    u_char  ip_vhl;
    u_char  ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
    u_char  ip_ttl;
    u_char  ip_p;
    u_short ip_sum;
    struct  in_addr ip_src,ip_dst;
};

struct tcphdr {
    u_short th_sport;
    u_short th_dport;
    u_long  th_seq;
    u_long  th_ack;
    u_char  th_offx2;
    u_char  th_flags;
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
};

struct udphdr {
    u_short uh_sport;
    u_short uh_dport;
    u_short uh_ulen;
    u_short uh_sum;
};

struct PacketInfo {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
};

#define ETHERTYPE_IP 0x0800

struct ether_header {
    u_char ether_dhost[6];
    u_char ether_shost[6];
    u_short ether_type;
};

struct HostStats {
    int packet_count = 0;
    std::chrono::steady_clock::time_point last_packet_time;
    std::unordered_map<uint16_t, int> port_scan_count;
};

std::unordered_map<std::string, HostStats> host_stats;

const int PACKET_THRESHOLD = 1000;
const int PORT_SCAN_THRESHOLD = 15;
const std::chrono::seconds TIME_WINDOW(60);

void check_dos_attack(const std::string& src_ip, const std::string& dst_ip) {
    auto& stats = host_stats[src_ip];
    auto current_time = std::chrono::steady_clock::now();

    if (stats.packet_count == 0) {
        stats.last_packet_time = current_time;
    }

    stats.packet_count++;

    if (std::chrono::duration_cast<std::chrono::seconds>(current_time - stats.last_packet_time) >= TIME_WINDOW) {
        if (stats.packet_count > PACKET_THRESHOLD) {
            std::cout << "ALERT: Possible DoS attack detected from " << src_ip << " to " << dst_ip
                      << " (" << stats.packet_count << " packets in " << TIME_WINDOW.count() << " seconds)\n";
        }
        stats.packet_count = 0;
        stats.last_packet_time = current_time;
    }
}

void check_port_scan(const std::string& src_ip, const std::string& dst_ip, uint16_t dst_port) {
    auto& stats = host_stats[src_ip];
    stats.port_scan_count[dst_port]++;

    if (stats.port_scan_count.size() > PORT_SCAN_THRESHOLD) {
        std::cout << "ALERT: Possible port scan detected from " << src_ip << " to " << dst_ip
                  << " (" << stats.port_scan_count.size() << " different ports)\n";
        stats.port_scan_count.clear();
    }
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header;
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;

    PacketInfo pinfo;

    eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return; // Not an IP packet, skip
    }

    ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    char ip_src[INET_ADDRSTRLEN];
    char ip_dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), ip_src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), ip_dst, INET_ADDRSTRLEN);
    pinfo.src_ip = ip_src;
    pinfo.dst_ip = ip_dst;
    pinfo.protocol = ip_header->ip_p;

    switch (ip_header->ip_p) {
        case IPPROTO_TCP:
            tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            pinfo.src_port = ntohs(tcp_header->th_sport);
            pinfo.dst_port = ntohs(tcp_header->th_dport);
            break;
        case IPPROTO_UDP:
            udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            pinfo.src_port = ntohs(udp_header->uh_sport);
            pinfo.dst_port = ntohs(udp_header->uh_dport);
            break;
        default:
            pinfo.src_port = 0;
            pinfo.dst_port = 0;
    }

    // Check for potential attacks
    check_dos_attack(pinfo.src_ip, pinfo.dst_ip);
    check_port_scan(pinfo.src_ip, pinfo.dst_ip, pinfo.dst_port);
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize Winsock" << std::endl;
        return 1;
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Get the list of available devices
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }

    // Print the list of devices
    std::cout << "Available devices:" << std::endl;
    for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
        std::cout << d->name << " - " << (d->description ? d->description : "No description available") << std::endl;
    }

    // Ask the user to choose a device
    std::string dev_name;
    std::cout << "\nEnter the name of the device you want to monitor: ";
    std::cin >> dev_name;

    // Open the device for sniffing
    handle = pcap_open_live(dev_name.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Could not open device " << dev_name << ": " << errbuf << std::endl;
        return 2;
    }

    std::cout << "IDS is monitoring on device " << dev_name << "..." << std::endl;

    // Start capturing packets
    if (pcap_loop(handle, 0, packet_handler, nullptr) < 0) {
        std::cerr << "pcap_loop() failed: " << pcap_geterr(handle) << std::endl;
        return 3;
    }

    // Close the handle
    pcap_close(handle);

    WSACleanup();
    return 0;
}