#pragma once

#include <protocolCraft/Utilities/Json.hpp>

#include <ctime>
#include <shared_mutex>
#include <string>

class Conf
{
public:
    static const std::string server_address_key;
    static const std::string local_port_key;
    static const std::string text_file_log_key;
    static const std::string binary_file_log_key;
    static const std::string console_log_key;
    static const std::string replay_log_key;
    static const std::string raw_bytes_log_key;
    static const std::string online_key;
    static const std::string network_recap_to_console_key;
    static const std::string account_cache_key_key;
    static const std::string handshaking_key;
    static const std::string status_key;
    static const std::string login_key;
    static const std::string configuration_key;
    static const std::string play_key;
    static const std::string ignored_clientbound_key;
    static const std::string ignored_serverbound_key;
    static const std::string detailed_clientbound_key;
    static const std::string detailed_serverbound_key;

    static bool headless;
    static std::string conf_path;
    static std::shared_mutex conf_mutex;

public:
    static ProtocolCraft::Json::Value LoadConf();
    static void SaveConf(const ProtocolCraft::Json::Value& conf);
    static std::time_t GetModifiedTimestamp();
};
