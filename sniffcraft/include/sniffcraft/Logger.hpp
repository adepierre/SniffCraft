#pragma once

#include "enums.hpp"

#include <protocolCraft/enums.hpp>
#include <protocolCraft/Message.hpp>

#include <picojson/picojson.h>

#include <thread>
#include <mutex>
#include <fstream>
#include <memory>
#include <queue>
#include <chrono>
#include <set>
#include <ctime>
#include <condition_variable>

struct LogItem
{
    std::shared_ptr<ProtocolCraft::Message> msg;
    std::chrono::time_point<std::chrono::system_clock> date;
    ProtocolCraft::ConnectionState connection_state;
    Origin origin;
};

class Logger
{
public:
    Logger(const std::string &conf_path);
    ~Logger();
    void Log(const std::shared_ptr<ProtocolCraft::Message> msg, const ProtocolCraft::ConnectionState connection_state, const Origin origin);
    void SetServerName(const std::string& server_name_);

private:
    void LogConsume();
    void LoadConfig(const std::string& path, const bool refresh);
    void LoadPacketsFromJson(const picojson::value& value, const ProtocolCraft::ConnectionState connection_state);
    void SaveReplayMetadataFile() const;

private:
    std::chrono::time_point<std::chrono::system_clock> start_time;

    std::thread log_thread;
    std::mutex log_mutex;
    std::condition_variable log_condition;
    std::queue<LogItem> logging_queue;

    std::string logconf_path;
    std::string session_prefix;
    std::ofstream log_file;
    std::ofstream replay_file;
    bool is_running;
    bool log_to_console;
    bool log_to_replay;

    std::string server_name;

    std::time_t last_time_checked_log_file;
    std::time_t last_time_log_file_modified;

    std::map<std::pair<ProtocolCraft::ConnectionState, Origin>, std::set<int> > ignored_packets;
    std::map<std::pair<ProtocolCraft::ConnectionState, Origin>, std::set<int> > detailed_packets;
};
