#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <csignal>
#include <atomic>
#include "capture.h"
#include "dissector.h"
#include "profiler.h"

static std::atomic<bool> g_running{true};
static PacketCapture      g_capture;
static Dissector          g_dissector;
static BehavioralProfiler g_profiler;
static std::string        g_bridge = "http://localhost:8000";

void sigHandler(int) { g_running = false; g_capture.stop(); }

void post(const std::string& ep, const std::string& json) {
    std::string cmd = "curl -s -X POST " + g_bridge + ep +
                      " -H 'Content-Type: application/json' -d '" + json + "' > /dev/null 2>&1 &";
    system(cmd.c_str());
}

std::string verdictStr(Verdict v) {
    switch(v) { case Verdict::ALLOW: return "ALLOW"; case Verdict::DROP: return "DROP";
                case Verdict::LOG:   return "LOG";   case Verdict::ALERT: return "ALERT"; }
    return "ALLOW";
}

void onPacket(const uint8_t* data, size_t len, struct timeval ts) {
    if (!g_running) return;
    auto opt = g_dissector.parse(data, len, ts);
    if (!opt) return;
    const Packet& p = *opt;
    g_profiler.observe(p);
    std::string json = "{\"src_ip\":\""+p.ip.src_ip+"\",\"dst_ip\":\""+p.ip.dst_ip+"\","
        "\"src_port\":"+std::to_string(p.transport.src_port)+","
        "\"dst_port\":"+std::to_string(p.transport.dst_port)+","
        "\"protocol\":\""+(p.transport.is_tcp?"TCP":"UDP")+"\","
        "\"app_protocol\":\""+p.app.protocol+"\","
        "\"host\":\""+p.app.host+"\","
        "\"bytes\":"+std::to_string(p.raw_len)+","
        "\"verdict\":\"ALLOW\",\"module\":\"\",\"reason\":\"\"}";
    std::thread([json](){ post("/ingest/packet", json); }).detach();
}

int main(int argc, char* argv[]) {
    std::signal(SIGINT, sigHandler);
    bool demo = false; std::string src;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a=="--demo"   && i+1<argc) { demo=true; src=argv[++i]; }
        if (a=="--iface"  && i+1<argc) { src=argv[++i]; }
        if (a=="--bridge" && i+1<argc) { g_bridge=argv[++i]; }
    }
    if (src.empty()) {
        std::cerr << "Usage: netsentinel --demo <file.pcap>\n"
                  << "       netsentinel --iface <eth0>\n"; return 1;
    }
    std::cout << "[netsentinel] Bridge: " << g_bridge << "\n";
    std::thread([](){ while(g_running) {
        std::this_thread::sleep_for(std::chrono::seconds(60));
        // anomaly flush would go here
    }}).detach();
    if (demo) g_capture.startDemo(src, onPacket);
    else      g_capture.startLive(src, onPacket);
    return 0;
}
