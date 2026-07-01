#pragma once
#include <functional>
#include <string>
#include <pcap.h>
#include "types.h"

using RawPacketCallback = std::function<void(const uint8_t*, size_t, struct timeval)>;

class PacketCapture {
public:
    bool startLive(const std::string& iface, RawPacketCallback cb);
    bool startDemo(const std::string& pcap_file, RawPacketCallback cb);
    void stop();
private:
    pcap_t* handle_ = nullptr;
};
