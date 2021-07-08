#include "sniffcraft/Logger.hpp"

#include <sstream>
#include <iomanip>

#include <protocolCraft/MessageFactory.hpp>
#include <protocolCraft/Handler.hpp>
#include <sniffcraft/FileUtilities.hpp>

Logger::Logger(const std::string &conf_path)
{
    logconf_path = conf_path;
    LoadConfig(logconf_path, false);

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

    if (log_to_replay)
    {
        replay_file.close();
        SaveReplayMetadataFile();
    }

    if (log_thread.joinable())
    {
        log_thread.join();
    }
}

void Logger::Log(const std::shared_ptr<ProtocolCraft::Message> msg, const ProtocolCraft::ConnectionState connection_state, const Origin origin)
{
    std::lock_guard<std::mutex> log_guard(log_mutex);
    if (!log_file.is_open() || (log_to_replay && !replay_file.is_open()))
    {
        start_time = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(start_time);

        std::stringstream ss;
        ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d-%H-%M-%S");
        session_prefix = ss.str();

        if (!log_file.is_open())
        {
            log_file = std::ofstream(session_prefix + "_log.txt", std::ios::out);
        }
        if (log_to_replay && !replay_file.is_open())
        {
            replay_file = std::ofstream(session_prefix + "_replay.tmcpr", std::ios::out | std::ios::binary);
        }
    }

    logging_queue.push({ msg, std::chrono::system_clock::now(), connection_state, origin });
    log_condition.notify_all();
}

void Logger::SetServerName(const std::string& server_name_)
{
    server_name = server_name_;
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
            auto total_millisec = millisec;
            millisec -= sec * 1000;
            sec -= min * 60;
            min -= hours * 60;

            if (log_to_replay && item.origin == Origin::Server
                && (item.connection_state == ProtocolCraft::ConnectionState::Play ||
                    (item.connection_state == ProtocolCraft::ConnectionState::Login && item.msg->GetId() == 0x02)))
            {
                std::vector<unsigned char> packet;
                // Write ID + Packet data
                item.msg->Write(packet);

                // Get total size
                std::vector<unsigned char> packet_size;
                ProtocolCraft::WriteData<int>(packet.size(), packet_size);

                // Get timestamp in ms
                std::vector<unsigned char> timestamp;
                ProtocolCraft::WriteData<int>(total_millisec, timestamp);

                replay_file.write((char*)timestamp.data(), timestamp.size());
                replay_file.write((char*)packet_size.data(), packet_size.size());
                replay_file.write((char*)packet.data(), packet.size());
            }

            std::stringstream output;

            if (item.msg == nullptr)
            {
                output << "[" << hours << ":" << min << ":" << sec << ":" << millisec << "] "
                    << (item.origin == Origin::Server ? "[S --> C] " : "[C --> S] ");
                output << "UNKNOWN OR WRONGLY PARSED MESSAGE";
                const std::string output_str = output.str();
                log_file << output_str << std::endl;
                if (log_to_console)
                {
                    std::cout << output_str << std::endl;
                }
                continue;
            }

            const std::set<int>& ignored_set = ignored_packets[{item.connection_state, item.origin}];
            const bool is_ignored = ignored_set.find(item.msg->GetId()) != ignored_set.end();
            if (is_ignored)
            {
                continue;
            }

            const std::set<int>& detailed_set = detailed_packets[{item.connection_state, item.origin}];
            const bool is_detailed = detailed_set.find(item.msg->GetId()) != detailed_set.end();

            output << "[" << hours << ":" << min << ":" << sec << ":" << millisec << "] "
                << (item.origin == Origin::Server ? "[S --> C] " : "[C --> S] ");
            output << item.msg->GetName();
            if (is_detailed)
            {
                output << "\n" << item.msg->Serialize().serialize(true);
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
                LoadConfig(logconf_path, true);
            }
        }
    }
}

void Logger::LoadConfig(const std::string& path, const bool refresh)
{
    std::time_t modification_time = GetModifiedTimestamp(path);
    if (modification_time == -1 ||
        modification_time == last_time_log_file_modified)
    {
        return;
    }

    last_time_log_file_modified = modification_time;
    std::cout << "Loading updated conf file" << std::endl;

    std::stringstream ss;
    std::ifstream file;

    bool error = path == "";
    picojson::value json;

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
            ss << file.rdbuf();
            file.close();

            ss >> json;
            std::string err = picojson::get_last_error();

            if (!err.empty())
            {
                std::cerr << "Error parsing conf file at " << path << ".\n";
                std::cerr << err << "\n" << std::endl;
                error = true;
            }
            if (!error)
            {
                if (!json.is<picojson::object>())
                {
                    std::cerr << "Error parsing conf file at " << path << "." << std::endl;
                    error = true;
                }
            }
        }
    }

    //Create default conf
    if (error)
    {
        return;
    }

    const std::map<std::string, ProtocolCraft::ConnectionState> name_mapping = {
        {"Handshaking", ProtocolCraft::ConnectionState::Handshake},
        {"Status", ProtocolCraft::ConnectionState::Status},
        {"Login", ProtocolCraft::ConnectionState::Login},
        {"Play", ProtocolCraft::ConnectionState::Play}
    };

    const picojson::value::object& obj = json.get<picojson::object>();

    log_to_console = false;
    auto log_to_console_value = obj.find("LogToConsole");
    if (log_to_console_value == obj.end())
    {
        log_to_console = false;
    }
    else
    {
        log_to_console = log_to_console_value->second.get<bool>();
    }

    if (!refresh)
    {
        auto log_to_replay_file = obj.find("LogToReplay");
        if (log_to_console_value != obj.end())
        {
            log_to_replay = log_to_replay_file->second.get<bool>();
        }
    }

    for (auto it = name_mapping.begin(); it != name_mapping.end(); ++it)
    {
        auto it2 = obj.find(it->first);
        if (it2 != obj.end())
        {
            LoadPacketsFromJson(it2->second, it->second);
        }
        else
        {
            const picojson::value null_value = picojson::value();
            LoadPacketsFromJson(null_value, it->second);
        }
    }
}

void Logger::LoadPacketsFromJson(const picojson::value& value, const ProtocolCraft::ConnectionState connection_state)
{
    ignored_packets[{connection_state, Origin::Client}] = std::set<int>();
    ignored_packets[{connection_state, Origin::Server}] = std::set<int>();
    detailed_packets[{connection_state, Origin::Client}] = std::set<int>();
    detailed_packets[{connection_state, Origin::Server}] = std::set<int>();

    if (value.is<picojson::null>())
    {
        return;
    }

    if (value.contains("ignored_clientbound"))
    {
        const picojson::object& object2 = value.get<picojson::object>();
        if (object2.find("ignored_clientbound") != object2.end() && object2.at("ignored_clientbound").is<picojson::array>())
        {
            const picojson::array& ignored = object2.at("ignored_clientbound").get<picojson::array>();
            for (auto i = ignored.begin(); i != ignored.end(); i++)
            {
                if (i->is<double>())
                {
                    ignored_packets[{connection_state, Origin::Server}].insert(i->get<double>());
                }
                else if (i->is<std::string>())
                {
                    for (int j = 0; j < 100; ++j)
                    {
                        auto msg = ProtocolCraft::MessageFactory::CreateMessageClientbound(j, connection_state);
                        if (msg && msg->GetName() == i->get<std::string>())
                        {
                            ignored_packets[{connection_state, Origin::Server}].insert(j);
                        }
                    }
                }
            }
        }
    }
    if (value.contains("ignored_serverbound"))
    {
        const picojson::object& object2 = value.get<picojson::object>();
        if (object2.find("ignored_serverbound") != object2.end() && object2.at("ignored_serverbound").is<picojson::array>())
        {
            const picojson::array& ignored = object2.at("ignored_serverbound").get<picojson::array>();
            for (auto i = ignored.begin(); i != ignored.end(); i++)
            {
                if (i->is<double>())
                {
                    ignored_packets[{connection_state, Origin::Client}].insert(i->get<double>());
                }
                else if (i->is<std::string>())
                {
                    for (int j = 0; j < 100; ++j)
                    {
                        auto msg = ProtocolCraft::MessageFactory::CreateMessageServerbound(j, connection_state);
                        if (msg && msg->GetName() == i->get<std::string>())
                        {
                            ignored_packets[{connection_state, Origin::Client}].insert(j);
                        }
                    }
                }
            }
        }
    }
    if (value.contains("detailed_clientbound"))
    {
        const picojson::object& object2 = value.get<picojson::object>();
        if (object2.find("detailed_clientbound") != object2.end() && object2.at("detailed_clientbound").is<picojson::array>())
        {
            const picojson::array& ignored = object2.at("detailed_clientbound").get<picojson::array>();
            for (auto i = ignored.begin(); i != ignored.end(); i++)
            {
                if (i->is<double>())
                {
                    detailed_packets[{connection_state, Origin::Client}].insert(i->get<double>());
                }
                else if (i->is<std::string>())
                {
                    for (int j = 0; j < 100; ++j)
                    {
                        auto msg = ProtocolCraft::MessageFactory::CreateMessageClientbound(j, connection_state);
                        if (msg && msg->GetName() == i->get<std::string>())
                        {
                            detailed_packets[{connection_state, Origin::Server}].insert(j);
                        }
                    }
                }
            }
        }
    }
    if (value.contains("detailed_serverbound"))
    {
        const picojson::object& object2 = value.get<picojson::object>();
        if (object2.find("detailed_serverbound") != object2.end() && object2.at("detailed_serverbound").is<picojson::array>())
        {
            const picojson::array& ignored = object2.at("detailed_serverbound").get<picojson::array>();
            for (auto i = ignored.begin(); i != ignored.end(); i++)
            {
                if (i->is<double>())
                {
                    detailed_packets[{connection_state, Origin::Client}].insert(i->get<double>());
                }
                else if (i->is<std::string>())
                {
                    for (int j = 0; j < 100; ++j)
                    {
                        auto msg = ProtocolCraft::MessageFactory::CreateMessageServerbound(j, connection_state);
                        if (msg && msg->GetName() == i->get<std::string>())
                        {
                            detailed_packets[{connection_state, Origin::Client}].insert(j);
                        }
                    }
                }
            }
        }
    }
}

void Logger::SaveReplayMetadataFile() const
{
    std::ofstream metadata(session_prefix + "_metaData.json", std::ios::out);

    metadata << "{\"singleplayer\":false," 
             << "\"serverName\"" << server_name << ","
             << "\"duration\":" << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - start_time).count() << ","
             << "\"fileFormat\":\"MCPR\"," 
             << "\"fileFormatVersion\":14," 
             << "\"protocol\":" << PROTOCOL_VERSION << ","
             << "\"generator\":\"SniffCraft\"}";
    metadata.close();
}
