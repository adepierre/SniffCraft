#include "sniffcraft/ReplayModLogger.hpp"
#include "sniffcraft/Zip/ZeptoZip.hpp"

#include <sstream>
#include <iomanip>
#include <iostream>

#include <protocolCraft/MessageFactory.hpp>
#include <protocolCraft/Handler.hpp>
#include <sniffcraft/FileUtilities.hpp>

using namespace ProtocolCraft;

ReplayModLogger::ReplayModLogger(const std::string &conf_path)
{
    TryStart(conf_path);
}

ReplayModLogger::~ReplayModLogger()
{
    if (is_running)
    {
        is_running = false;
        log_condition.notify_all();

        while (!logging_queue.empty())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        if (log_thread.joinable())
        {
            log_thread.join();
        }
        replay_file.close();

        SaveReplayMetadataFile();
        WrapMCPRFile();
    }
}

void ReplayModLogger::Log(const std::shared_ptr<Message> msg, const ConnectionState connection_state, const Endpoint origin)
{
    if (!is_running)
    {
        return;
    }

    std::lock_guard<std::mutex> log_guard(log_mutex);
    if (!replay_file.is_open())
    {
        start_time = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(start_time);

        std::stringstream ss;
        ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d-%H-%M-%S");
        session_prefix = ss.str();
        replay_file = std::ofstream(session_prefix + "_recording.tmcpr", std::ios::out | std::ios::binary);
    }

    logging_queue.push({ msg, std::chrono::system_clock::now(), connection_state, origin });
    log_condition.notify_all();
}

void ReplayModLogger::SetServerName(const std::string& server_name_)
{
    server_name = server_name_;
}

void ReplayModLogger::LogConsume()
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

            if ((item.origin == Endpoint::Server || item.origin == Endpoint::SniffcraftToClient)
                && (item.connection_state == ConnectionState::Play ||
                    (item.connection_state == ConnectionState::Login && item.msg->GetId() == 0x02)))
            {
                std::vector<unsigned char> packet;
                // Write ID + Packet data
                item.msg->Write(packet);

                // Get total size
                std::vector<unsigned char> packet_size;
                WriteData<int>(static_cast<int>(packet.size()), packet_size);

                // Get timestamp in ms
                std::vector<unsigned char> timestamp;
                WriteData<int>(static_cast<int>(total_millisec), timestamp);

                replay_file.write((char*)timestamp.data(), timestamp.size());
                replay_file.write((char*)packet_size.data(), packet_size.size());
                replay_file.write((char*)packet.data(), packet.size());
            }
        }
    }
}

void ReplayModLogger::TryStart(const std::string& conf_path)
{
    std::ifstream file;

    bool error = conf_path == "";
    Json::Value json;

    if (!error)
    {
        file.open(conf_path);
        if (!file.is_open())
        {
            std::cerr << "Error trying to open conf file: " << conf_path << "." << std::endl;
            error = true;
        }
        if (!error)
        {
            file >> json;
            file.close();

            if (!json.is_object())
            {
                std::cerr << "Error parsing conf file at " << conf_path << "." << std::endl;
                error = true;
            }
        }
    }

    //Create default conf
    if (error)
    {
        return;
    }

    if (json.contains("LogToReplay") && json["LogToReplay"].get<bool>())
    {
        is_running = true;
        log_thread = std::thread(&ReplayModLogger::LogConsume, this);
    }
}

void ReplayModLogger::SaveReplayMetadataFile() const
{
    std::ofstream metadata(session_prefix + "_metaData.json", std::ios::out);
    auto now = std::chrono::system_clock::now();

    metadata << "{\"singleplayer\":false," 
             << "\"serverName\":\"" << server_name << "\","
             << "\"duration\":" << std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count() << ","
             << "\"date\":" << std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() << ","
             << "\"fileFormat\":\"MCPR\"," 
             << "\"fileFormatVersion\":14," 
             << "\"protocol\":\"" << PROTOCOL_VERSION << "\","
             << "\"generator\":\"SniffCraft\"}";
    metadata.close();
}

void ReplayModLogger::WrapMCPRFile() const
{
    ZeptoZip::CreateZipArchive(session_prefix + ".mcpr", { session_prefix + "_metaData.json", session_prefix + "_recording.tmcpr" },
        { "metaData.json", "recording.tmcpr" });
    std::remove((session_prefix + "_metaData.json").c_str());
    std::remove((session_prefix + "_recording.tmcpr").c_str());
}
