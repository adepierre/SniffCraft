#include "sniffcraft/ReplayModLogger.hpp"
#include "sniffcraft/Zip/ZeptoZip.hpp"

#include <iomanip>
#include <iostream>
#include <sstream>

using namespace ProtocolCraft;

ReplayModLogger::ReplayModLogger()
{
    is_running = true;
    log_thread = std::thread(&ReplayModLogger::LogConsume, this);
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

void ReplayModLogger::Log(const std::shared_ptr<Packet> packet, const ConnectionState connection_state, const Endpoint origin)
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

    logging_queue.push({ packet, std::chrono::system_clock::now(), connection_state, origin });
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

            if (item.origin == Endpoint::Server || item.origin == Endpoint::SniffcraftToClient)
            {
                std::vector<unsigned char> packet;
                // Write ID + Packet data
                item.packet->Write(packet);

                // Get timestamp in ms
                std::vector<unsigned char> header;
                WriteData<int>(static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(item.date - start_time).count()), header);
                // Get total size
                WriteData<int>(static_cast<int>(packet.size()), header);

                replay_file.write(reinterpret_cast<const char*>(header.data()), header.size());
                replay_file.write(reinterpret_cast<const char*>(packet.data()), packet.size());
            }
        }
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
