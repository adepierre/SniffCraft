#pragma once

#include "sniffcraft/enums.hpp"
#include "sniffcraft/LogItem.hpp"

#include <protocolCraft/enums.hpp>
#include <protocolCraft/Packet.hpp>

#include <thread>
#include <mutex>
#include <fstream>
#include <memory>
#include <queue>
#include <chrono>
#include <set>
#include <ctime>
#include <condition_variable>

class ReplayModLogger
{
public:
    ReplayModLogger();
    ~ReplayModLogger();
    void Log(const std::shared_ptr<ProtocolCraft::Packet> packet, const ProtocolCraft::ConnectionState connection_state, const Endpoint origin);
    void SetServerName(const std::string& server_name_);

private:
    void LogConsume();
    void SaveReplayMetadataFile() const;
    void WrapMCPRFile() const;

private:
    std::chrono::time_point<std::chrono::system_clock> start_time;

    std::thread log_thread;
    std::mutex log_mutex;
    std::condition_variable log_condition;
    std::queue<LogItem> logging_queue;

    std::string session_prefix;
    std::ofstream replay_file;
    bool is_running;

    std::string server_name;
};
