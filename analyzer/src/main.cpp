#include <iostream>
#include <iomanip>
#include <ctime>
#include <fstream>
#include <unordered_map>
#include <string>
#include "pcap_reader.h"
#include "packet_parser.h"

using namespace PacketAnalyzer;

// ============================================================================
// Web-integration additions (report.json + output.pcap generation)
// ----------------------------------------------------------------------------
// Everything below this banner is purely additive: it does not change how
// packets are read or parsed. It only collects simple counters while the
// existing packet loop runs, then serializes them to report.json and writes
// a copy of every packet that was read to output.pcap so the web frontend
// has something to download. No parsing logic was modified.
// ============================================================================

namespace WebReport {

// Minimal JSON string escaping (filenames / IPs are the only free-form text)
std::string jsonEscape(const std::string& input) {
    std::string out;
    out.reserve(input.size() + 8);
    for (char c : input) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

struct TopEntry {
    std::string ip;
    uint64_t count = 0;
};

TopEntry findTop(const std::unordered_map<std::string, uint64_t>& counts) {
    TopEntry top;
    for (const auto& [ip, count] : counts) {
        if (count > top.count) {
            top.ip = ip;
            top.count = count;
        }
    }
    return top;
}

double pct(uint64_t part, uint64_t total) {
    if (total == 0) return 0.0;
    return (static_cast<double>(part) * 100.0) / static_cast<double>(total);
}

struct ReportStats {
    uint64_t total_packets = 0;
    uint64_t parse_errors = 0;
    uint64_t tcp_packets = 0;
    uint64_t udp_packets = 0;
    uint64_t icmp_packets = 0;
    uint64_t other_packets = 0;
    uint64_t http_packets = 0;
    uint64_t https_packets = 0;
    uint64_t dns_packets = 0;
    uint64_t total_bytes = 0;
    std::unordered_map<std::string, uint64_t> src_ip_counts;
    std::unordered_map<std::string, uint64_t> dest_ip_counts;
};

void writeReportJson(const std::string& path,
                      const std::string& source_file,
                      const ReportStats& s) {
    TopEntry top_src = findTop(s.src_ip_counts);
    TopEntry top_dst = findTop(s.dest_ip_counts);

    std::ofstream out(path, std::ios::trunc);
    out << "{\n";
    out << "  \"source_file\": \"" << jsonEscape(source_file) << "\",\n";
    out << "  \"total_packets\": " << s.total_packets << ",\n";
    out << "  \"total_bytes\": " << s.total_bytes << ",\n";
    out << "  \"parse_errors\": " << s.parse_errors << ",\n";
    out << "  \"protocol_counts\": {\n";
    out << "    \"tcp\": " << s.tcp_packets << ",\n";
    out << "    \"udp\": " << s.udp_packets << ",\n";
    out << "    \"icmp\": " << s.icmp_packets << ",\n";
    out << "    \"other\": " << s.other_packets << "\n";
    out << "  },\n";
    out << "  \"application_counts\": {\n";
    out << "    \"http\": " << s.http_packets << ",\n";
    out << "    \"https\": " << s.https_packets << ",\n";
    out << "    \"dns\": " << s.dns_packets << "\n";
    out << "  },\n";
    out << "  \"protocol_distribution\": {\n";
    out << std::fixed << std::setprecision(2);
    out << "    \"TCP\": " << pct(s.tcp_packets, s.total_packets) << ",\n";
    out << "    \"UDP\": " << pct(s.udp_packets, s.total_packets) << ",\n";
    out << "    \"ICMP\": " << pct(s.icmp_packets, s.total_packets) << ",\n";
    out << "    \"Other\": " << pct(s.other_packets, s.total_packets) << "\n";
    out << "  },\n";
    out << "  \"top_source_ip\": {\n";
    out << "    \"ip\": \"" << jsonEscape(top_src.ip) << "\",\n";
    out << "    \"count\": " << top_src.count << "\n";
    out << "  },\n";
    out << "  \"top_destination_ip\": {\n";
    out << "    \"ip\": \"" << jsonEscape(top_dst.ip) << "\",\n";
    out << "    \"count\": " << top_dst.count << "\n";
    out << "  }\n";
    out << "}\n";
    out.close();
}

} // namespace WebReport

void printPacketSummary(const ParsedPacket& pkt, int packet_num) {
    // Format timestamp
    std::time_t time = pkt.timestamp_sec;
    std::tm* tm = std::localtime(&time);
    
    std::cout << "\n========== Packet #" << packet_num << " ==========\n";
    std::cout << "Time: " << std::put_time(tm, "%Y-%m-%d %H:%M:%S") 
              << "." << std::setfill('0') << std::setw(6) << pkt.timestamp_usec << "\n";
    
    // Ethernet layer
    std::cout << "\n[Ethernet]\n";
    std::cout << "  Source MAC:      " << pkt.src_mac << "\n";
    std::cout << "  Destination MAC: " << pkt.dest_mac << "\n";
    std::cout << "  EtherType:       0x" << std::hex << std::setfill('0') 
              << std::setw(4) << pkt.ether_type << std::dec;
    
    if (pkt.ether_type == EtherType::IPv4) {
        std::cout << " (IPv4)";
    } else if (pkt.ether_type == EtherType::IPv6) {
        std::cout << " (IPv6)";
    } else if (pkt.ether_type == EtherType::ARP) {
        std::cout << " (ARP)";
    }
    std::cout << "\n";
    
    // IP layer
    if (pkt.has_ip) {
        std::cout << "\n[IPv" << static_cast<int>(pkt.ip_version) << "]\n";
        std::cout << "  Source IP:      " << pkt.src_ip << "\n";
        std::cout << "  Destination IP: " << pkt.dest_ip << "\n";
        std::cout << "  Protocol:       " << PacketParser::protocolToString(pkt.protocol) << "\n";
        std::cout << "  TTL:            " << static_cast<int>(pkt.ttl) << "\n";
    }
    
    // TCP layer
    if (pkt.has_tcp) {
        std::cout << "\n[TCP]\n";
        std::cout << "  Source Port:      " << pkt.src_port << "\n";
        std::cout << "  Destination Port: " << pkt.dest_port << "\n";
        std::cout << "  Sequence Number:  " << pkt.seq_number << "\n";
        std::cout << "  Ack Number:       " << pkt.ack_number << "\n";
        std::cout << "  Flags:            " << PacketParser::tcpFlagsToString(pkt.tcp_flags) << "\n";
    }
    
    // UDP layer
    if (pkt.has_udp) {
        std::cout << "\n[UDP]\n";
        std::cout << "  Source Port:      " << pkt.src_port << "\n";
        std::cout << "  Destination Port: " << pkt.dest_port << "\n";
    }
    
    // Payload info
    if (pkt.payload_length > 0) {
        std::cout << "\n[Payload]\n";
        std::cout << "  Length: " << pkt.payload_length << " bytes\n";
        
        // Print first 32 bytes of payload as hex (if present)
        std::cout << "  Preview: ";
        size_t preview_len = std::min(pkt.payload_length, static_cast<size_t>(32));
        for (size_t i = 0; i < preview_len; i++) {
            std::cout << std::hex << std::setfill('0') << std::setw(2) 
                      << static_cast<int>(pkt.payload_data[i]) << " ";
        }
        if (pkt.payload_length > 32) {
            std::cout << "...";
        }
        std::cout << std::dec << "\n";
    }
}

void printUsage(const char* program_name) {
    std::cout << "Usage: " << program_name << " <pcap_file> [max_packets]\n";
    std::cout << "\nArguments:\n";
    std::cout << "  pcap_file   - Path to a .pcap file captured by Wireshark\n";
    std::cout << "  max_packets - (Optional) Maximum number of packets to display\n";
    std::cout << "\nExample:\n";
    std::cout << "  " << program_name << " capture.pcap\n";
    std::cout << "  " << program_name << " capture.pcap 10\n";
}

int main(int argc, char* argv[]) {
    std::cout << "====================================\n";
    std::cout << "     Packet Analyzer v1.0\n";
    std::cout << "====================================\n\n";
    
    // Check command line arguments
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }
    
    std::string filename = argv[1];
    int max_packets = -1;  // -1 means no limit
    
    if (argc >= 3) {
        max_packets = std::stoi(argv[2]);
    }
    
    // Open the PCAP file
    PcapReader reader;
    if (!reader.open(filename)) {
        return 1;
    }

    // --- Web-integration: open output.pcap as a passthrough capture file ---
    // Every packet successfully read from the input is also written here so
    // the web UI has a real .pcap artifact to offer for download.
    std::ofstream output_pcap("output.pcap", std::ios::binary | std::ios::trunc);
    if (output_pcap.is_open()) {
        const PcapGlobalHeader& gh = reader.getGlobalHeader();
        output_pcap.write(reinterpret_cast<const char*>(&gh), sizeof(PcapGlobalHeader));
    } else {
        std::cerr << "Warning: Could not open output.pcap for writing\n";
    }
    WebReport::ReportStats stats;
    // -------------------------------------------------------------------

    std::cout << "\n--- Reading packets ---\n";
    
    // Read and parse packets
    RawPacket raw_packet;
    ParsedPacket parsed_packet;
    int packet_count = 0;
    int parse_errors = 0;
    
    while (reader.readNextPacket(raw_packet)) {
        packet_count++;

        // --- Web-integration: passthrough copy + stats collection ---
        if (output_pcap.is_open()) {
            output_pcap.write(reinterpret_cast<const char*>(&raw_packet.header), sizeof(PcapPacketHeader));
            if (!raw_packet.data.empty()) {
                output_pcap.write(reinterpret_cast<const char*>(raw_packet.data.data()), raw_packet.data.size());
            }
        }
        stats.total_packets++;
        stats.total_bytes += raw_packet.header.orig_len;
        // -------------------------------------------------------------
        
        if (PacketParser::parse(raw_packet, parsed_packet)) {
            printPacketSummary(parsed_packet, packet_count);

            // --- Web-integration: classify protocol/application + top IPs ---
            if (parsed_packet.has_ip) {
                if (parsed_packet.protocol == Protocol::TCP) {
                    stats.tcp_packets++;
                } else if (parsed_packet.protocol == Protocol::UDP) {
                    stats.udp_packets++;
                } else if (parsed_packet.protocol == Protocol::ICMP) {
                    stats.icmp_packets++;
                } else {
                    stats.other_packets++;
                }

                if (!parsed_packet.src_ip.empty()) {
                    stats.src_ip_counts[parsed_packet.src_ip]++;
                }
                if (!parsed_packet.dest_ip.empty()) {
                    stats.dest_ip_counts[parsed_packet.dest_ip]++;
                }
            } else {
                stats.other_packets++;
            }

            if (parsed_packet.has_tcp || parsed_packet.has_udp) {
                bool is_port = [&](uint16_t port) {
                    return parsed_packet.src_port == port || parsed_packet.dest_port == port;
                }(80);
                if (parsed_packet.has_tcp && is_port) {
                    stats.http_packets++;
                }
                if (parsed_packet.has_tcp &&
                    (parsed_packet.src_port == 443 || parsed_packet.dest_port == 443)) {
                    stats.https_packets++;
                }
                if (parsed_packet.src_port == 53 || parsed_packet.dest_port == 53) {
                    stats.dns_packets++;
                }
            }
            // -----------------------------------------------------------------
        } else {
            std::cerr << "Warning: Failed to parse packet #" << packet_count << "\n";
            parse_errors++;
        }
        
        // Check if we've reached the limit
        if (max_packets > 0 && packet_count >= max_packets) {
            std::cout << "\n(Stopped after " << max_packets << " packets)\n";
            break;
        }
    }
    
    // Summary
    std::cout << "\n====================================\n";
    std::cout << "Summary:\n";
    std::cout << "  Total packets read:  " << packet_count << "\n";
    std::cout << "  Parse errors:        " << parse_errors << "\n";
    std::cout << "  TCP packets:         " << stats.tcp_packets << "\n";
    std::cout << "  UDP packets:         " << stats.udp_packets << "\n";
    std::cout << "  ICMP packets:        " << stats.icmp_packets << "\n";
    std::cout << "  HTTP packets:        " << stats.http_packets << "\n";
    std::cout << "  HTTPS packets:       " << stats.https_packets << "\n";
    std::cout << "  DNS packets:         " << stats.dns_packets << "\n";
    std::cout << "====================================\n";

    reader.close();
    if (output_pcap.is_open()) {
        output_pcap.close();
        std::cout << "Wrote passthrough capture: output.pcap\n";
    }

    // --- Web-integration: persist report.json for the FastAPI backend ---
    stats.parse_errors = static_cast<uint64_t>(parse_errors);
    WebReport::writeReportJson("report.json", filename, stats);
    std::cout << "Wrote analysis report: report.json\n";
    // ---------------------------------------------------------------------

    return 0;
}
