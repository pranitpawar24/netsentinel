#include "capture.h"
#include <iostream>

struct CaptureContext { RawPacketCallback cb; };

static void pcapCallback(u_char* user, const struct pcap_pkthdr* hdr, const u_char* data) {
    reinterpret_cast<CaptureContext*>(user)->cb(data, hdr->caplen, hdr->ts);
}

bool PacketCapture::startLive(const std::string& iface, RawPacketCallback cb) {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle_ = pcap_open_live(iface.c_str(), 65535, 1, 1000, errbuf);
    if (!handle_) { std::cerr << "[capture] " << errbuf << "\n"; return false; }
    CaptureContext ctx{cb};
    pcap_loop(handle_, -1, pcapCallback, reinterpret_cast<u_char*>(&ctx));
    return true;
}

bool PacketCapture::startDemo(const std::string& file, RawPacketCallback cb) {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle_ = pcap_open_offline(file.c_str(), errbuf);
    if (!handle_) { std::cerr << "[capture] " << errbuf << "\n"; return false; }
    std::cout << "[capture] Demo mode: replaying " << file << "\n";
    CaptureContext ctx{cb};
    pcap_loop(handle_, -1, pcapCallback, reinterpret_cast<u_char*>(&ctx));
    return true;
}

void PacketCapture::stop() {
    if (handle_) { pcap_breakloop(handle_); pcap_close(handle_); handle_ = nullptr; }
}
