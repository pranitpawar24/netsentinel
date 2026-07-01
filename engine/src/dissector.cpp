#include "dissector.h"
#include <cstring>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string_view>

static constexpr size_t ETH_HLEN = 14;

std::optional<Packet> Dissector::parse(const uint8_t* data, size_t len, struct timeval ts) {
    Packet pkt;
    pkt.timestamp = std::chrono::system_clock::from_time_t(ts.tv_sec)
                  + std::chrono::microseconds(ts.tv_usec);
    pkt.raw_len = len;
    if (!parseEthernet(data, len, pkt)) return std::nullopt;
    return pkt;
}

bool Dissector::parseEthernet(const uint8_t* data, size_t len, Packet& pkt) {
    if (len < ETH_HLEN) return false;
    uint16_t et = (data[12] << 8) | data[13];
    if (et != 0x0800) return false;
    return parseIP(data + ETH_HLEN, len - ETH_HLEN, pkt);
}

bool Dissector::parseIP(const uint8_t* data, size_t len, Packet& pkt) {
    if (len < sizeof(struct ip)) return false;
    const auto* iph = reinterpret_cast<const struct ip*>(data);
    size_t ihl = iph->ip_hl * 4;
    if (len < ihl) return false;
    char s[INET_ADDRSTRLEN], d[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->ip_src, s, sizeof(s));
    inet_ntop(AF_INET, &iph->ip_dst, d, sizeof(d));
    pkt.ip = {s, d, iph->ip_p, ntohs(iph->ip_len), iph->ip_ttl};
    bool ok = false;
    if (iph->ip_p == IPPROTO_TCP)      ok = parseTCP(data+ihl, len-ihl, pkt);
    else if (iph->ip_p == IPPROTO_UDP) ok = parseUDP(data+ihl, len-ihl, pkt);
    if (ok) parseAppLayer(pkt);
    return ok;
}

bool Dissector::parseTCP(const uint8_t* data, size_t len, Packet& pkt) {
    if (len < sizeof(struct tcphdr)) return false;
    const auto* h = reinterpret_cast<const struct tcphdr*>(data);
    size_t hl = h->th_off * 4;
    pkt.transport = {ntohs(h->th_sport), ntohs(h->th_dport), true,
                     bool(h->th_flags&TH_SYN), bool(h->th_flags&TH_ACK),
                     bool(h->th_flags&TH_FIN), bool(h->th_flags&TH_RST), ntohl(h->th_seq)};
    const uint8_t* p = data + hl;
    pkt.app.payload.assign(p, p + (len - hl));
    return true;
}

bool Dissector::parseUDP(const uint8_t* data, size_t len, Packet& pkt) {
    if (len < sizeof(struct udphdr)) return false;
    const auto* h = reinterpret_cast<const struct udphdr*>(data);
    pkt.transport = {ntohs(h->uh_sport), ntohs(h->uh_dport), false, false, false, false, false, 0};
    const uint8_t* p = data + sizeof(struct udphdr);
    pkt.app.payload.assign(p, p + (len - sizeof(struct udphdr)));
    return true;
}

void Dissector::parseAppLayer(Packet& pkt) {
    pkt.app.protocol = "UNKNOWN";
    if (tryHTTP(pkt)) return;
    if (tryDNS(pkt))  return;
    tryTLS(pkt);
}

bool Dissector::tryHTTP(Packet& pkt) {
    if (pkt.app.payload.empty()) return false;
    std::string_view sv(reinterpret_cast<const char*>(pkt.app.payload.data()), pkt.app.payload.size());
    for (auto m : {"GET ", "POST ", "PUT ", "DELETE ", "HEAD "}) {
        if (sv.starts_with(m)) {
            pkt.app.protocol = "HTTP";
            pkt.app.method = std::string(m); pkt.app.method.pop_back();
            auto hp = sv.find("Host: ");
            if (hp != sv.npos) { auto e = sv.find("\r\n", hp+6); pkt.app.host = std::string(sv.substr(hp+6, e-hp-6)); }
            auto s1 = sv.find(' '), s2 = sv.find(' ', s1+1);
            if (s1 != sv.npos && s2 != sv.npos) pkt.app.uri = std::string(sv.substr(s1+1, s2-s1-1));
            return true;
        }
    }
    return false;
}

bool Dissector::tryDNS(Packet& pkt) {
    if (pkt.transport.dst_port != 53 && pkt.transport.src_port != 53) return false;
    if (pkt.app.payload.size() < 12) return false;
    pkt.app.protocol = "DNS";
    const uint8_t* p = pkt.app.payload.data() + 12;
    const uint8_t* e = pkt.app.payload.data() + pkt.app.payload.size();
    std::string name;
    while (p < e && *p) { uint8_t l=*p++; if (!name.empty()) name+='.'; name.append(reinterpret_cast<const char*>(p),l); p+=l; }
    pkt.app.host = name;
    return true;
}

bool Dissector::tryTLS(Packet& pkt) {
    if (pkt.app.payload.size() < 5) return false;
    if (pkt.app.payload[0] != 0x16 || pkt.app.payload[1] != 0x03) return false;
    pkt.app.protocol = "TLS";
    auto& d = pkt.app.payload;
    for (size_t i = 5; i+9 < d.size(); i++) {
        if (d[i]==0x00 && d[i+1]==0x00) {
            size_t nl = (d[i+7]<<8)|d[i+8];
            if (i+9+nl <= d.size()) { pkt.app.tls_sni = std::string(reinterpret_cast<const char*>(d.data()+i+9), nl); pkt.app.host = pkt.app.tls_sni; }
            break;
        }
    }
    return true;
}
