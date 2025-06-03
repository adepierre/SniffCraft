#include "sniffcraft/conf.hpp"

#include <filesystem>
#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>

#ifndef WIN32
#include <unistd.h>
#else
#define stat _stat
#endif

const std::string Conf::server_address_key = "ServerAddress";
const std::string Conf::local_port_key = "LocalPort";
const std::string Conf::text_file_log_key = "LogToTxtFile";
const std::string Conf::binary_file_log_key = "LogToBinFile";
const std::string Conf::console_log_key = "LogToConsole";
const std::string Conf::replay_log_key = "LogToReplay";
const std::string Conf::raw_bytes_log_key = "LogRawBytes";
const std::string Conf::online_key = "Online";
const std::string Conf::network_recap_to_console_key = "NetworkRecapToConsole";
const std::string Conf::account_cache_key_key = "MicrosoftAccountCacheKey";
const std::string Conf::handshaking_key = "Handshaking";
const std::string Conf::status_key = "Status";
const std::string Conf::login_key = "Login";
const std::string Conf::configuration_key = "Configuration";
const std::string Conf::play_key = "Play";
const std::string Conf::ignored_clientbound_key = "ignored_clientbound";
const std::string Conf::ignored_serverbound_key = "ignored_serverbound";
const std::string Conf::detailed_clientbound_key = "detailed_clientbound";
const std::string Conf::detailed_serverbound_key = "detailed_serverbound";

#ifdef WITH_GUI
bool Conf::headless = false;
#else
bool Conf::headless = true;
#endif

std::string Conf::conf_path = "";

std::shared_mutex Conf::conf_mutex;

ProtocolCraft::Json::Value Conf::LoadConf()
{
    if (conf_path.empty())
    {
#if defined(__APPLE__)
        conf_path = "/Users/" + std::string(std::getenv("USER")) + "/Library/Application Support/SniffCraft/conf.json";
#else
        conf_path = "conf.json";
#endif
    }

    // Create file if it doesn't exist
    if (!std::filesystem::exists(conf_path))
    {
        std::filesystem::path parent_directory = std::filesystem::path(conf_path).parent_path();
        if (!parent_directory.empty()) {
          std::filesystem::create_directories(parent_directory);
        }
        std::ofstream outfile(conf_path, std::ios::out);
        outfile << ProtocolCraft::Json::Value().Dump(4);
    }

    std::ifstream file = std::ifstream(conf_path, std::ios::in);
    if (!file.is_open())
    {
        throw std::runtime_error("Error trying to open conf file at: " + conf_path);
    }
    ProtocolCraft::Json::Value json;
    file >> json;
    file.close();

    if (!json.is_object())
        json = ProtocolCraft::Json::Object();
    // Set default values if missing
    if (!json.contains(server_address_key))
        json[server_address_key] = "127.0.0.1:25565";
    if (!json.contains(local_port_key))
        json[local_port_key] = 25555;
    if (!json.contains(text_file_log_key))
        json[text_file_log_key] = true;
    if (!json.contains(binary_file_log_key))
        json[binary_file_log_key] = false;
    if (!json.contains(console_log_key))
        json[console_log_key] = true;
    if (!json.contains(replay_log_key))
        json[replay_log_key] = false;
    if (!json.contains(raw_bytes_log_key))
        json[raw_bytes_log_key] = false;
    if (!json.contains(online_key))
        json[online_key] = false;
    if (!json.contains(account_cache_key_key))
        json[account_cache_key_key] = "";
    if (!json.contains(network_recap_to_console_key))
        json[network_recap_to_console_key] = false;
    ProtocolCraft::Json::Value packet_lists = {
        { ignored_clientbound_key, ProtocolCraft::Json::Array() },
        { ignored_serverbound_key, ProtocolCraft::Json::Array() },
        { detailed_clientbound_key, ProtocolCraft::Json::Array() },
        { detailed_serverbound_key, ProtocolCraft::Json::Array() },
    };
    if (!json.contains(handshaking_key))
        json[handshaking_key] = packet_lists;
    if (!json.contains(status_key))
        json[status_key] = packet_lists;
    if (!json.contains(login_key))
        json[login_key] = packet_lists;
    if (!json.contains(play_key))
        json[play_key] = packet_lists;
    if (!json.contains(configuration_key))
        json[configuration_key] = packet_lists;

    return json;
}

void Conf::SaveConf(const ProtocolCraft::Json::Value& conf)
{
    std::ofstream file = std::ofstream(conf_path, std::ios::out);
    if (!file.is_open())
    {
        throw std::runtime_error("Error trying to open conf file at: " + conf_path);
    }

    file << conf.Dump(4);
    file.close();
}

std::time_t Conf::GetModifiedTimestamp()
{
    struct stat result;
    if (stat(conf_path.c_str(), &result) == 0)
    {
        return result.st_mtime;
    }
    return -1;
}
