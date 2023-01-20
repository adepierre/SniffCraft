#include "sniffcraft/Logger.hpp"

#include <iostream>
#include <sstream>
#include <iomanip>

#include <protocolCraft/MessageFactory.hpp>
#include <protocolCraft/Handler.hpp>
#include <sniffcraft/FileUtilities.hpp>

using namespace ProtocolCraft;

Logger::Logger(const std::string &conf_path)
{
    logconf_path = conf_path;
    LoadConfig(logconf_path);

    is_running = true;
    log_thread = std::thread(&Logger::LogConsume, this);
}

Logger::~Logger()
{
    is_running = false;
    log_condition.notify_all();

    while (!logging_queue.empty())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    log_file.close();

    if (log_thread.joinable())
    {
        log_thread.join();
    }
}

void Logger::Log(const std::shared_ptr<Message> msg, const ConnectionState connection_state, const Endpoint origin)
{
    std::lock_guard<std::mutex> log_guard(log_mutex);
    if (!log_file.is_open())
    {
        start_time = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(start_time);

        std::stringstream ss;
        ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d-%H-%M-%S");

        log_file = std::ofstream(ss.str() + "_log.txt", std::ios::out);
    }

    logging_queue.push({ msg, std::chrono::system_clock::now(), connection_state, origin });
    log_condition.notify_all();
}

void Logger::LogConsume()
{
    while (is_running)
    {
        {
            std::unique_lock<std::mutex> lock(log_mutex);
            log_condition.wait(lock);
        }
        while (!logging_queue.empty())
        {
            LogItem item;
            {
                std::lock_guard<std::mutex> log_guard(log_mutex);
                item = logging_queue.front();
                logging_queue.pop();
            }

            auto hours = std::chrono::duration_cast<std::chrono::hours>(item.date - start_time).count();
            auto min = std::chrono::duration_cast<std::chrono::minutes>(item.date - start_time).count();
            auto sec = std::chrono::duration_cast<std::chrono::seconds>(item.date - start_time).count();
            auto millisec = std::chrono::duration_cast<std::chrono::milliseconds>(item.date - start_time).count();

            millisec -= sec * 1000;
            sec -= min * 60;
            min -= hours * 60;

            std::stringstream output;

            if (item.msg == nullptr)
            {
                output 
                    << "["
                    << hours
                    << ":"
                    << std::setw(2) << std::setfill('0') << min
                    << ":"
                    << std::setw(2) << std::setfill('0') << sec
                    << ":"
                    << std::setw(3) << std::setfill('0') << millisec
                    << "] "
                    << OriginToString(item.origin) << " ";
                output << "UNKNOWN OR WRONGLY PARSED MESSAGE";
                const std::string output_str = output.str();
                log_file << output_str << std::endl;
                if (log_to_console)
                {
                    std::cout << output_str << std::endl;
                }
                continue;
            }

            const std::set<int>& ignored_set = ignored_packets[{item.connection_state, SimpleOrigin(item.origin)}];
            const bool is_ignored = ignored_set.find(item.msg->GetId()) != ignored_set.end();
            if (is_ignored)
            {
                continue;
            }

            const std::set<int>& detailed_set = detailed_packets[{item.connection_state, SimpleOrigin(item.origin)}];
            const bool is_detailed = detailed_set.find(item.msg->GetId()) != detailed_set.end();

            output 
                << "["
                << hours
                << ":"
                << std::setw(2) << std::setfill('0') << min
                << ":"
                << std::setw(2) << std::setfill('0') << sec
                << ":"
                << std::setw(3) << std::setfill('0') << millisec
                << "] "
                << OriginToString(item.origin) << " ";
            output << item.msg->GetName();
            if (log_raw_bytes)
            {
                output << '\n';
                std::vector<unsigned char> bytes;
                item.msg->Write(bytes);
                for (size_t i = 0; i < bytes.size(); ++i)
                {
                    output << "0x" << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(bytes[i]) << (i == bytes.size() - 1 ? "" : " ");
                }
            }
            if (is_detailed)
            {
                output << "\n" << item.msg->Serialize().Dump(4);
            }

            const std::string output_str = output.str();
            log_file << output_str << std::endl;
            if (log_to_console)
            {
                std::cout << output_str << std::endl;
            }

            // Every 5 seconds, check if the conf file has changed and reload it if needed
            std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            if (now - last_time_checked_log_file > 5)
            {
                last_time_checked_log_file = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
                LoadConfig(logconf_path);
            }
        }
    }
}

void Logger::LoadConfig(const std::string& path)
{
    std::time_t modification_time = GetModifiedTimestamp(path);
    if (modification_time == -1 ||
        modification_time == last_time_log_file_modified)
    {
        return;
    }

    last_time_log_file_modified = modification_time;
    std::cout << "Loading updated conf file..." << std::endl;

    std::ifstream file;
    bool error = path == "";
    Json::Value json;

    if (!error)
    {
        file.open(path);
        if (!file.is_open())
        {
            std::cerr << "Error trying to open conf file: " << path << "." << std::endl;
            error = true;
        }
        if (!error)
        {
            file >> json;

            if (!json.is_object())
            {
                std::cerr << "Error parsing conf file at " << path << "." << std::endl;
                error = true;
            }
        }
        file.close();
    }

    //Create default conf
    if (error)
    {
        return;
    }

    const std::map<std::string, ConnectionState> name_mapping = {
        {"Handshaking", ConnectionState::Handshake},
        {"Status", ConnectionState::Status},
        {"Login", ConnectionState::Login},
        {"Play", ConnectionState::Play}
    };

    log_to_console = false;

    if (!json.contains("LogToConsole"))
    {
        log_to_console = false;
    }
    else
    {
        log_to_console = json["LogToConsole"].get<bool>();
    }

    log_raw_bytes = false;

    if (!json.contains("LogRawBytes"))
    {
        log_raw_bytes = false;
    }
    else
    {
        log_raw_bytes = json["LogRawBytes"].get<bool>();
    }

    for (auto it = name_mapping.begin(); it != name_mapping.end(); ++it)
    {
        if (json.contains(it->first))
        {
            LoadPacketsFromJson(json[it->first], it->second);
        }
        else
        {
            LoadPacketsFromJson(Json::Value(), it->second);
        }
    }
    std::cout << "Conf file loaded!" << std::endl;
}

void Logger::LoadPacketsFromJson(const Json::Value& value, const ConnectionState connection_state)
{
    ignored_packets[{connection_state, Endpoint::Client}] = std::set<int>();
    ignored_packets[{connection_state, Endpoint::Server}] = std::set<int>();
    detailed_packets[{connection_state, Endpoint::Client}] = std::set<int>();
    detailed_packets[{connection_state, Endpoint::Server}] = std::set<int>();

    if (value.is_null())
    {
        return;
    }

    if (value.contains("ignored_clientbound") && value["ignored_clientbound"].is_array())
    {
        for (const auto& val : value["ignored_clientbound"].get_array())
        {
            if (val.is_number())
            {
                ignored_packets[{connection_state, Endpoint::Server}].insert(val.get<int>());
            }
            else if (val.is_string())
            {
                // Search for the matching id
                for (int j = 0; j < 150; ++j)
                {
                    const std::shared_ptr<Message> msg = CreateClientboundMessage(connection_state, j);
                    if (msg && msg->GetName() == val.get<std::string>())
                    {
                        ignored_packets[{connection_state, Endpoint::Server}].insert(j);
                        break;
                    }
                }
            }
        }
    }

    if (value.contains("ignored_serverbound") && value["ignored_serverbound"].is_array())
    {
        for (const auto& val : value["ignored_serverbound"].get_array())
        {
            if (val.is_number())
            {
                ignored_packets[{connection_state, Endpoint::Client}].insert(val.get<int>());
            }
            else if (val.is_string())
            {
                // Search for the matching id
                for (int j = 0; j < 150; ++j)
                {
                    const std::shared_ptr<Message> msg = CreateServerboundMessage(connection_state, j);
                    if (msg && msg->GetName() == val.get<std::string>())
                    {
                        ignored_packets[{connection_state, Endpoint::Client}].insert(j);
                        break;
                    }
                }
            }
        }
    }

    if (value.contains("detailed_clientbound") && value["detailed_clientbound"].is_array())
    {
        for (const auto& val : value["detailed_clientbound"].get_array())
        {
            if (val.is_number())
            {
                detailed_packets[{connection_state, Endpoint::Server}].insert(val.get<int>());
            }
            else if (val.is_string())
            {
                // Search for the matching id
                for (int j = 0; j < 150; ++j)
                {
                    const std::shared_ptr<Message> msg = CreateClientboundMessage(connection_state, j);
                    if (msg && msg->GetName() == val.get<std::string>())
                    {
                        detailed_packets[{connection_state, Endpoint::Server}].insert(j);
                        break;
                    }
                }
            }
        }
    }

    if (value.contains("detailed_serverbound") && value["detailed_serverbound"].is_array())
    {
        for (const auto& val : value["detailed_serverbound"].get_array())
        {
            if (val.is_number())
            {
                detailed_packets[{connection_state, Endpoint::Client}].insert(val.get<int>());
            }
            else if (val.is_string())
            {
                // Search for the matching id
                for (int j = 0; j < 150; ++j)
                {
                    const std::shared_ptr<Message> msg = CreateServerboundMessage(connection_state, j);
                    if (msg && msg->GetName() == val.get<std::string>())
                    {
                        detailed_packets[{connection_state, Endpoint::Client}].insert(j);
                        break;
                    }
                }
            }
        }
    }
}

std::string Logger::OriginToString(const Endpoint origin) const
{
    switch (origin)
    {
    case Endpoint::Client:
        return "[C --> S]";
    case Endpoint::Server:
        return "[S --> C]";
    case Endpoint::SniffcraftToClient:
        return "[(SC) --> C]";
    case Endpoint::SniffcraftToServer:
        return "[(SC) --> S]";
    case Endpoint::ClientToSniffcraft:
        return "[C --> (SC)]";
    case Endpoint::ServerToSniffcraft:
        return "[S --> (SC)]";
    default:
        return "";
    }
}

Endpoint Logger::SimpleOrigin(const Endpoint origin) const
{
    switch (origin)
    {
    case Endpoint::Client:
    case Endpoint::Server:
        return origin;
    case Endpoint::SniffcraftToClient:
        return Endpoint::Server;
    case Endpoint::SniffcraftToServer:
        return Endpoint::Client;
    case Endpoint::ServerToSniffcraft:
        return Endpoint::Server;
    case Endpoint::ClientToSniffcraft:
        return Endpoint::Client;
    default:
        return Endpoint::Client;
    }
}
