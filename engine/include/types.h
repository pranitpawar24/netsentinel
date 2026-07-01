#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <chrono>

struct IPHeader {
    std::string src_ip, dst_ip;
    uint8_t  protocol;
    uint16_t total_len;
    uint8_t  ttl;
};

struct TransportHeader {
    uint16_t src_port, dst_port;
    bool is_tcp, syn, ack, fin, rst;
    uint32_t seq_num;
};

struct AppLayer {
    std::string protocol;
    std::string method, host, uri, tls_sni;
    std::vector<uint8_t> payload;
};

struct Packet {
    std::chrono::system_clock::time_point timestamp;
    IPHeader        ip;
    TransportHeader transport;
    AppLayer        app;
    size_t          raw_len;
};

enum class Verdict { ALLOW, DROP, LOG, ALERT };

struct InspectionResult {
    Verdict     verdict = Verdict::ALLOW;
    std::string module, reason;
    float       anomaly_score = 0.0f;
};
