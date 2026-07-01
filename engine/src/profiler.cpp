#include "profiler.h"
#include <algorithm>
#include <sstream>
#include <chrono>
#include <ctime>

void BehavioralProfiler::observe(const Packet& pkt) {
    std::lock_guard<std::mutex> lock(mutex_);
    const std::string& ip = pkt.ip.src_ip;
    auto& s = current_[ip];
    auto& ports = current_ports_[ip];
    s.bytes_sent += pkt.raw_len;
    s.packet_count++;
    if (std::find(ports.begin(), ports.end(), pkt.transport.dst_port) == ports.end())
        ports.push_back(pkt.transport.dst_port);
    s.unique_ports = ports.size();
    auto t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    s.hour_of_day = localtime(&t)->tm_hour;
    float n = s.packet_count;
    if (pkt.app.protocol == "UNKNOWN")
        s.unknown_ratio = (s.unknown_ratio * (n-1) + 1.0f) / n;
}

std::vector<AnomalyAlert> BehavioralProfiler::flushAlerts() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<AnomalyAlert> alerts;
    for (auto& [ip, s] : current_) {
        auto& p = profiles_[ip];
        if (p.bytes_sent.count >= 10) {
            std::vector<AnomalyAlert::Deviation> devs;
            float score = 0;
            auto check = [&](const std::string& m, double v, RunningStats& rs, const std::string& u) {
                if (rs.count < 5) return;
                double z = rs.zScore(v);
                if (z > 2.0) { devs.push_back({m, std::to_string(v)+u+" (avg:"+std::to_string(rs.mean)+u+")", z}); score += z; }
            };
            check("bytes_sent",   s.bytes_sent,   p.bytes_sent,   "B");
            check("packet_count", s.packet_count, p.packet_count, "pkt");
            check("unique_ports", s.unique_ports, p.unique_ports, "ports");
            check("unknown_ratio",s.unknown_ratio,p.unknown_ratio,"");
            bool odd = std::find(p.active_hours.begin(),p.active_hours.end(),s.hour_of_day)==p.active_hours.end() && p.active_hours.size()>20;
            if (odd) { devs.push_back({"active_hour","Hour "+std::to_string(s.hour_of_day)+" never seen",3.0}); score+=3; }
            if (score >= ALERT_THRESHOLD)
                alerts.push_back({ip, classifyAnomaly(devs), score, devs});
        }
        p.bytes_sent.update(s.bytes_sent); p.packet_count.update(s.packet_count);
        p.unique_ports.update(s.unique_ports); p.unknown_ratio.update(s.unknown_ratio);
        p.active_hours.push_back(s.hour_of_day);
    }
    current_.clear(); current_ports_.clear();
    return alerts;
}

std::string BehavioralProfiler::classifyAnomaly(const std::vector<AnomalyAlert::Deviation>& devs) {
    bool ports=false, unk=false, bytes=false, hour=false;
    for (auto& d : devs) {
        if (d.metric=="unique_ports")  ports=true;
        if (d.metric=="unknown_ratio") unk=true;
        if (d.metric=="bytes_sent")    bytes=true;
        if (d.metric=="active_hour")   hour=true;
    }
    if (ports&&unk)   return "POSSIBLE_PORT_SCAN";
    if (bytes&&hour)  return "POSSIBLE_EXFILTRATION";
    if (bytes)        return "UNUSUAL_TRAFFIC_VOLUME";
    if (hour)         return "UNUSUAL_ACTIVE_HOUR";
    return "BEHAVIORAL_ANOMALY";
}
