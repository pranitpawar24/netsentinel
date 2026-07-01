#pragma once
#include "types.h"
#include <string>
#include <unordered_map>
#include <deque>
#include <vector>
#include <mutex>
#include <cmath>

struct RunningStats {
    uint64_t count = 0;
    double mean = 0.0, M2 = 0.0;
    void update(double x) {
        count++;
        double d = x - mean; mean += d / count;
        M2 += d * (x - mean);
    }
    double stddev() const { return count > 1 ? std::sqrt(M2/(count-1)) : 0.0; }
    double zScore(double x) const { double s = stddev(); return s > 0 ? std::abs((x-mean)/s) : 0.0; }
};

struct TrafficSample {
    uint64_t bytes_sent = 0;
    uint32_t packet_count = 0, unique_ports = 0, hour_of_day = 0;
    float unknown_ratio = 0.0f;
};

struct IPProfile {
    RunningStats bytes_sent, packet_count, unique_ports, unknown_ratio;
    std::vector<uint32_t> active_hours;
    std::deque<TrafficSample> window;
};

struct AnomalyAlert {
    std::string ip, verdict;
    float score;
    struct Deviation { std::string metric, description; double z_score; };
    std::vector<Deviation> deviations;
};

class BehavioralProfiler {
public:
    static constexpr float ALERT_THRESHOLD = 3.5f;
    void observe(const Packet& pkt);
    std::vector<AnomalyAlert> flushAlerts();
private:
    std::unordered_map<std::string, IPProfile> profiles_;
    std::unordered_map<std::string, TrafficSample> current_;
    std::unordered_map<std::string, std::vector<uint16_t>> current_ports_;
    std::mutex mutex_;
    std::string classifyAnomaly(const std::vector<AnomalyAlert::Deviation>&);
};
