#pragma once

#include "sniffcraft/enums.hpp"
#include "sniffcraft/LogItem.hpp"

#include <protocolCraft/enums.hpp>
#include <protocolCraft/Message.hpp>

#include <nlohmann/json.hpp>

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
    void Log(const std::shared_ptr<ProtocolCraft::Message> msg, const ProtocolCraft::ConnectionState connection_state, const Origin origin);

private:
    void LogConsume();
    void LoadConfig(const std::string& path);
    void LoadPacketsFromJson(const nlohmann::json& value, const ProtocolCraft::ConnectionState connection_state);

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

    std::time_t last_time_checked_log_file;
    std::time_t last_time_log_file_modified;

    std::map<std::pair<ProtocolCraft::ConnectionState, Origin>, std::set<int> > ignored_packets;
    std::map<std::pair<ProtocolCraft::ConnectionState, Origin>, std::set<int> > detailed_packets;
};
