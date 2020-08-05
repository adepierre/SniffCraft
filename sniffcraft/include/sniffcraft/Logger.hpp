#pragma once

#include "enums.hpp"
#include "Handler.hpp"

#include <protocolCraft/enums.hpp>
#include <protocolCraft/Message.hpp>

#include <picojson/picojson.h>

#include <thread>
#include <mutex>
#include <fstream>
#include <memory>
#include <deque>
#include <chrono>
#include <set>
#include <ctime>

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

private:
    void LogConsume();
    void LoadConfig(const std::string& path);
    void LoadPacketsFromJson(const picojson::value& value, const ProtocolCraft::ConnectionState connection_state);

private:
    std::chrono::time_point<std::chrono::system_clock> start_time;

    std::thread log_thread;
    std::mutex log_mutex;
    std::condition_variable log_condition;
    std::deque<LogItem> logging_queue;

    std::string logfile_path;
    std::ofstream log_file;
    bool is_running;
    bool log_to_console;

    std::time_t last_time_checked_log_file;
    std::time_t last_time_log_file_modified;

    std::map<std::pair<ProtocolCraft::ConnectionState, Origin>, std::set<int> > ignored_packets;
    std::map<std::pair<ProtocolCraft::ConnectionState, Origin>, std::set<int> > detailed_packets;
};
