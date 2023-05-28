#pragma once

#include "sniffcraft/enums.hpp"
#include "sniffcraft/LogItem.hpp"
#include "sniffcraft/NetworkRecapItem.hpp"

#include <protocolCraft/enums.hpp>
#include <protocolCraft/Message.hpp>
#include <protocolCraft/Utilities/Json.hpp>

#include <thread>
#include <mutex>
#include <fstream>
#include <memory>
#include <queue>
#include <chrono>
#include <set>
#include <ctime>
#include <condition_variable>

class Logger
{
public:
    Logger(const std::string &conf_path);
    ~Logger();
    void Log(const std::shared_ptr<ProtocolCraft::Message>& msg, const ProtocolCraft::ConnectionState connection_state, const Endpoint origin, const size_t bandwidth_bytes);

private:
    void LogConsume();
    void LoadConfig(const std::string& path);
    void LoadPacketsFromJson(const ProtocolCraft::Json::Value& value, const ProtocolCraft::ConnectionState connection_state);
    std::string OriginToString(const Endpoint origin) const;
    Endpoint SimpleOrigin(const Endpoint origin) const;
    std::string GenerateNetworkRecap(const int max_entry = -1, const int max_name_size = -1) const;

private:
    std::chrono::time_point<std::chrono::system_clock> start_time;

    std::thread log_thread;
    std::mutex log_mutex;
    std::condition_variable log_condition;
    std::queue<LogItem> logging_queue;

    std::string logconf_path;
    std::ofstream log_file;
    bool is_running;
    bool log_to_console;
    bool log_raw_bytes;
    bool log_network_recap_console;

    std::time_t last_time_checked_conf_file;
    std::time_t last_time_conf_file_modified;
    std::time_t last_time_network_recap_printed;

    std::map<std::pair<ProtocolCraft::ConnectionState, Endpoint>, std::set<int> > ignored_packets;
    std::map<std::pair<ProtocolCraft::ConnectionState, Endpoint>, std::set<int> > detailed_packets;

    std::map<std::string, NetworkRecapItem> clientbound_network_recap_data;
    std::map<std::string, NetworkRecapItem> serverbound_network_recap_data;
    NetworkRecapItem clientbound_total_network_recap;
    NetworkRecapItem serverbound_total_network_recap;
};
