#pragma once
#include "types.h"
#include <optional>

class Dissector {
public:
    std::optional<Packet> parse(const uint8_t* data, size_t len, struct timeval ts);
private:
    bool parseEthernet(const uint8_t*, size_t, Packet&);
    bool parseIP(const uint8_t*, size_t, Packet&);
    bool parseTCP(const uint8_t*, size_t, Packet&);
    bool parseUDP(const uint8_t*, size_t, Packet&);
    void parseAppLayer(Packet&);
    bool tryHTTP(Packet&);
    bool tryDNS(Packet&);
    bool tryTLS(Packet&);
};
