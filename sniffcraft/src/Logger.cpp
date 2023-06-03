#include "sniffcraft/Logger.hpp"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <cmath>

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

    log_file << GenerateNetworkRecap() << std::endl;

    log_file.close();

    if (log_thread.joinable())
    {
        log_thread.join();
    }
}

void Logger::Log(const std::shared_ptr<Message>& msg, const ConnectionState connection_state, const Endpoint origin, const size_t bandwidth_bytes)
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

    logging_queue.push({ msg, std::chrono::system_clock::now(), connection_state, origin, bandwidth_bytes });
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

            // Update network recap data
            if (item.connection_state == ConnectionState::Play && item.bandwidth_bytes > 0)
            {
                const Endpoint simple_origin = SimpleOrigin(item.origin);
                std::map<std::string, NetworkRecapItem>& recap_data_map = simple_origin == Endpoint::Server ? clientbound_network_recap_data : serverbound_network_recap_data;

                // Get Network recap key (packet name + identifier if custom payload)
                std::string map_key(item.msg->GetName());
                if (simple_origin == Endpoint::Server && item.msg->GetId() == ProtocolCraft::ClientboundCustomPayloadPacket::packet_id)
                {
                    std::shared_ptr<ProtocolCraft::ClientboundCustomPayloadPacket> custom_payload = std::dynamic_pointer_cast<ProtocolCraft::ClientboundCustomPayloadPacket>(item.msg);
                    map_key += "|" + custom_payload->GetIdentifier();
                }
                else if (simple_origin == Endpoint::Client && item.msg->GetId() == ProtocolCraft::ServerboundCustomPayloadPacket::packet_id)
                {
                    std::shared_ptr<ProtocolCraft::ServerboundCustomPayloadPacket> custom_payload = std::dynamic_pointer_cast<ProtocolCraft::ServerboundCustomPayloadPacket>(item.msg);
                    map_key += "|" + custom_payload->GetIdentifier();
                }

                NetworkRecapItem& recap = recap_data_map[map_key];
                recap.count += 1;
                recap.bandwidth_bytes += item.bandwidth_bytes;

                NetworkRecapItem& total_recap_item = simple_origin == Endpoint::Server ? clientbound_total_network_recap : serverbound_total_network_recap;
                total_recap_item.count += 1;
                total_recap_item.bandwidth_bytes += item.bandwidth_bytes;
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
            if (now - last_time_checked_conf_file > 5)
            {
                last_time_checked_conf_file = now;
                LoadConfig(logconf_path);
            }

            // Every 10 seconds, print network recap if option is true
            if (log_network_recap_console && now - last_time_network_recap_printed > 10)
            {
                last_time_network_recap_printed = now;
                std::cout << GenerateNetworkRecap(10, 18) << std::endl;
            }
        }
    }
}

void Logger::LoadConfig(const std::string& path)
{
    std::time_t modification_time = GetModifiedTimestamp(path);
    if (modification_time == -1 ||
        modification_time == last_time_conf_file_modified)
    {
        return;
    }

    last_time_conf_file_modified = modification_time;
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

    if (!json.contains("NetworkRecapToConsole"))
    {
        log_network_recap_console = false;
    }
    else
    {
        log_network_recap_console = json["NetworkRecapToConsole"].get<bool>();
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

using map_it = std::map<std::string, NetworkRecapItem>::const_iterator;
std::string ReportTable(
    const NetworkRecapItem& clientbound_total,
    const NetworkRecapItem& serverbound_total,
    const std::vector<map_it>& clientbound_items,
    const std::vector<map_it>& serverbound_items,
    const int max_entry,
    const int max_name_size
)
{
    // Get max width of column "Name"
    int clientbound_max_name_length = 0;
    for (int i = 0; i < clientbound_items.size(); ++i)
    {
        if (i == max_entry)
        {
            break;
        }
        if (clientbound_items[i]->first.size() > clientbound_max_name_length)
        {
            clientbound_max_name_length = clientbound_items[i]->first.size();
        }
    }
    int serverbound_max_name_length = 0;
    for (int i = 0; i < serverbound_items.size(); ++i)
    {
        if (i == max_entry)
        {
            break;
        }
        if (serverbound_items[i]->first.size() > serverbound_max_name_length)
        {
            serverbound_max_name_length = serverbound_items[i]->first.size();
        }
    }

    // In case there is no entry, "Total".size() is the width of the column
    clientbound_max_name_length = std::max(5, clientbound_max_name_length);
    serverbound_max_name_length = std::max(5, serverbound_max_name_length);
    if (max_name_size > -1)
    {
        clientbound_max_name_length = std::min(max_name_size, clientbound_max_name_length);
        serverbound_max_name_length = std::min(max_name_size, serverbound_max_name_length);
    }

    // We don't need to make sure  it's > "Count".size() because there is already the (XX.XX%) content in the column
    const int clientbound_max_count_size = clientbound_total.count == 0 ? 1 : static_cast<int>(std::log10(clientbound_total.count) + 1);
    const int serverbound_max_count_size = serverbound_total.count == 0 ? 1 : static_cast<int>(std::log10(serverbound_total.count) + 1);

    // We don't need to make sure  it's > "Bandwidth".size() because there is already the (XX.XX%) content in the column
    const int clientbound_max_bandwidth_size = clientbound_total.bandwidth_bytes == 0 ? 1 : static_cast<int>(std::log10(clientbound_total.bandwidth_bytes) + 1);
    const int serverbound_max_bandwidth_size = serverbound_total.bandwidth_bytes == 0 ? 1 : static_cast<int>(std::log10(serverbound_total.bandwidth_bytes) + 1);

    const int clientbound_total_width = clientbound_max_name_length + clientbound_max_count_size + clientbound_max_bandwidth_size + 26;
    const int serverbound_total_width = serverbound_max_name_length + serverbound_max_count_size + serverbound_max_bandwidth_size + 26;

    std::stringstream output;
    // +=============================+  +=============================+
    output << '+';
    for (int i = 0; i < clientbound_total_width; ++i)
    {
        output << '=';
    }
    output << "+  +";
    for (int i = 0; i < serverbound_total_width; ++i)
    {
        output << '=';
    }
    output << "+\n";

    // |      Client --> Server      |  |      Server --> Client      |
    constexpr int header_size = 17;
    output << '|';
    for (int i = 0; i < (clientbound_total_width - header_size) / 2; ++i)
    {
        output << ' ';
    }
    output << "Server -" << (clientbound_total_width % 2 ? "" : "-") << "-> Client";
    for (int i = 0; i < (clientbound_total_width - header_size) / 2; ++i)
    {
        output << ' ';
    }
    output << "|  |";
    for (int i = 0; i < (serverbound_total_width - header_size) / 2; ++i)
    {
        output << ' ';
    }
    output << "Client -" << (serverbound_total_width % 2 ? "" : "-") << "-> Server";
    for (int i = 0; i < (serverbound_total_width - header_size) / 2; ++i)
    {
        output << ' ';
    }
    output << "|\n";

    // +=========================+  +===========================+
    output << '+';
    for (int i = 0; i < clientbound_total_width; ++i)
    {
        output << '=';
    }
    output << "+  +";
    for (int i = 0; i < serverbound_total_width; ++i)
    {
        output << '=';
    }
    output << "+\n";

    // | Name | Count | Bandwidth |  | Name | Count | Bandwidth |
    output << '|';
    for (int i = 0; i < clientbound_max_name_length / 2 - 1; ++i)
    {
        output << ' ';
    }
    output << "Name";
    for (int i = 0; i < clientbound_max_name_length / 2 - 1 + clientbound_max_name_length % 2; ++i)
    {
        output << ' ';
    }
    output << '|';
    for (int i = 0; i < 3 + clientbound_max_count_size / 2; ++i)
    {
        output << ' ';
    }
    output << "Count";
    for (int i = 0; i < 3 + clientbound_max_count_size / 2 + clientbound_max_count_size % 2; ++i)
    {
        output << ' ';
    }
    output << '|';
    for (int i = 0; i < 1 + clientbound_max_bandwidth_size / 2; ++i)
    {
        output << ' ';
    }
    output << "Bandwidth";
    for (int i = 0; i < 1 + clientbound_max_bandwidth_size / 2 + clientbound_max_bandwidth_size % 2; ++i)
    {
        output << ' ';
    }
    output << "|  |";
    for (int i = 0; i < serverbound_max_name_length / 2 - 1; ++i)
    {
        output << ' ';
    }
    output << "Name";
    for (int i = 0; i < serverbound_max_name_length / 2 - 1 + serverbound_max_name_length % 2; ++i)
    {
        output << ' ';
    }
    output << '|';
    for (int i = 0; i < 3 + serverbound_max_count_size / 2; ++i)
    {
        output << ' ';
    }
    output << "Count";
    for (int i = 0; i < 3 + serverbound_max_count_size / 2 + serverbound_max_count_size % 2; ++i)
    {
        output << ' ';
    }
    output << '|';
    for (int i = 0; i < 1 + serverbound_max_bandwidth_size / 2; ++i)
    {
        output << ' ';
    }
    output << "Bandwidth";
    for (int i = 0; i < 1 + serverbound_max_bandwidth_size / 2 + serverbound_max_bandwidth_size % 2; ++i)
    {
        output << ' ';
    }
    output << "|\n";

    // +------+------+------+  +------+------+------+
    output << '+';
    for (int i = 0; i < clientbound_max_name_length + 2; ++i)
    {
        output << '-';
    }
    output << '+';
    for (int i = 0; i < clientbound_max_count_size + 2 + 9; ++i)
    {
        output << '-';
    }
    output << '+';
    for (int i = 0; i < clientbound_max_bandwidth_size + 2 + 9; ++i)
    {
        output << '-';
    }
    output << "+  +";
    for (int i = 0; i < serverbound_max_name_length + 2; ++i)
    {
        output << '-';
    }
    output << '+';
    for (int i = 0; i < serverbound_max_count_size + 2 + 9; ++i)
    {
        output << '-';
    }
    output << '+';
    for (int i = 0; i < serverbound_max_bandwidth_size + 2 + 9; ++i)
    {
        output << '-';
    }
    output << "+\n";

    // | Total | NNNNN (100.0%) | NNNNN (100.0%) |  | Total | NNNNN (100.0%) | NNNNN (100.0%) |
    output << '|';
    output << " Total";
    for (int i = 0; i < 1 + clientbound_max_name_length - 5; ++i)
    {
        output << ' ';
    }
    output << "| "
        << std::setw(clientbound_max_count_size) << clientbound_total.count
        << " (100.0%) ";
    output << "| "
        << std::setw(clientbound_max_bandwidth_size) << clientbound_total.bandwidth_bytes
        << " (100.0%) ";
    output << "|  |";
    output << " Total";
    for (int i = 0; i < 1 + serverbound_max_name_length - 5; ++i)
    {
        output << ' ';
    }
    output << "| "
        << std::setw(serverbound_max_count_size) << serverbound_total.count
        << " (100.0%) ";
    output << "| "
        << std::setw(serverbound_max_bandwidth_size) << serverbound_total.bandwidth_bytes
        << " (100.0%) ";
    output << "|\n";

    // | Name | NNNNN (XX.XX%) | NNNNN (XX.XX%) |  | Name | NNNNN (XX.XX%) | NNNNN (XX.XX%) |
    for (int idx = 0; idx < std::max(clientbound_items.size(), serverbound_items.size()); ++idx)
    {
        if (idx == max_entry)
        {
            break;
        }
        output << "| ";
        if (idx < clientbound_items.size())
        {
            if (max_name_size > -1 && clientbound_items[idx]->first.size() > max_name_size)
            {
                output << clientbound_items[idx]->first.substr(0, std::max(1, max_name_size - 3)) << "... ";
            }
            else
            {
                output << clientbound_items[idx]->first;
                for (int i = 0; i < 1 + clientbound_max_name_length - clientbound_items[idx]->first.size(); ++i)
                {
                    output << ' ';
                }
            }
            output << "| ";
            output << std::setw(clientbound_max_count_size) << clientbound_items[idx]->second.count
                << " ("
                << std::setw(5) << std::fixed << std::setprecision(2) << 100.0f * static_cast<float>(clientbound_items[idx]->second.count) / clientbound_total.count
                << "%) | ";
            output << std::setw(clientbound_max_bandwidth_size) << clientbound_items[idx]->second.bandwidth_bytes
                << " ("
                << std::setw(5) << std::fixed << std::setprecision(2) << 100.0f * static_cast<float>(clientbound_items[idx]->second.bandwidth_bytes) / clientbound_total.bandwidth_bytes
                << "%) |";
        }
        else
        {
            for (int i = 0; i < clientbound_max_name_length; ++i)
            {
                output << ' ';
            }
            output << " | ";
            for (int i = 0; i < clientbound_max_count_size + 9; ++i)
            {
                output << ' ';
            }
            output << " | ";
            for (int i = 0; i < clientbound_max_bandwidth_size + 9; ++i)
            {
                output << ' ';
            }
            output << " |";
        }
        output << "  ";
        output << "| ";
        if (idx < serverbound_items.size())
        {
            if (max_name_size > -1 && serverbound_items[idx]->first.size() > max_name_size)
            {
                output << serverbound_items[idx]->first.substr(0, std::max(1, max_name_size - 3)) << "... ";
            }
            else
            {
                output << serverbound_items[idx]->first;
                for (int i = 0; i < 1 + serverbound_max_name_length - serverbound_items[idx]->first.size(); ++i)
                {
                    output << ' ';
                }
            }
            output << "| ";
            output << std::setw(serverbound_max_count_size) << serverbound_items[idx]->second.count
                << " ("
                << std::setw(5) << std::fixed << std::setprecision(2) << 100.0f * static_cast<float>(serverbound_items[idx]->second.count) / serverbound_total.count
                << "%) | ";
            output << std::setw(serverbound_max_bandwidth_size) << serverbound_items[idx]->second.bandwidth_bytes
                << " ("
                << std::setw(5) << std::fixed << std::setprecision(2) << 100.0f * static_cast<float>(serverbound_items[idx]->second.bandwidth_bytes) / serverbound_total.bandwidth_bytes
                << "%) |";
        }
        else
        {
            for (int i = 0; i < serverbound_max_name_length; ++i)
            {
                output << ' ';
            }
            output << " | ";
            for (int i = 0; i < serverbound_max_count_size + 9; ++i)
            {
                output << ' ';
            }
            output << " | ";
            for (int i = 0; i < serverbound_max_bandwidth_size + 9; ++i)
            {
                output << ' ';
            }
            output << " |";
        }
        output << "\n";
    }

    // +------+------+------+  +------+------+------+
    output << '+';
    for (int i = 0; i < clientbound_max_name_length + 2; ++i)
    {
        output << '-';
    }
    output << '+';
    for (int i = 0; i < clientbound_max_count_size + 2 + 9; ++i)
    {
        output << '-';
    }
    output << '+';
    for (int i = 0; i < clientbound_max_bandwidth_size + 2 + 9; ++i)
    {
        output << '-';
    }
    output << "+  +";
    for (int i = 0; i < serverbound_max_name_length + 2; ++i)
    {
        output << '-';
    }
    output << '+';
    for (int i = 0; i < serverbound_max_count_size + 2 + 9; ++i)
    {
        output << '-';
    }
    output << '+';
    for (int i = 0; i < serverbound_max_bandwidth_size + 2 + 9; ++i)
    {
        output << '-';
    }
    output << "+\n";

    return output.str();
}

std::string Logger::GenerateNetworkRecap(const int max_entry, const int max_name_size) const
{
    std::vector<map_it> clientbound_recap_iterators_sorted_count;
    std::vector<map_it> clientbound_recap_iterators_sorted_size;
    clientbound_recap_iterators_sorted_count.reserve(clientbound_network_recap_data.size());
    clientbound_recap_iterators_sorted_size.reserve(clientbound_network_recap_data.size());
    for (auto it = clientbound_network_recap_data.begin(); it != clientbound_network_recap_data.end(); ++it)
    {
        clientbound_recap_iterators_sorted_count.push_back(it);
        clientbound_recap_iterators_sorted_size.push_back(it);
    }
    std::sort(clientbound_recap_iterators_sorted_count.begin(), clientbound_recap_iterators_sorted_count.end(),
        [](const map_it& a, const map_it& b)
        {
            return a->second.count > b->second.count;
        });
    std::sort(clientbound_recap_iterators_sorted_size.begin(), clientbound_recap_iterators_sorted_size.end(),
        [](const map_it& a, const map_it& b)
        {
            return a->second.bandwidth_bytes > b->second.bandwidth_bytes;
        });


    std::vector<map_it> serverbound_recap_iterators_sorted_count;
    std::vector<map_it> serverbound_recap_iterators_sorted_size;
    serverbound_recap_iterators_sorted_count.reserve(serverbound_network_recap_data.size());
    serverbound_recap_iterators_sorted_size.reserve(serverbound_network_recap_data.size());
    for (auto it = serverbound_network_recap_data.begin(); it != serverbound_network_recap_data.end(); ++it)
    {
        serverbound_recap_iterators_sorted_count.push_back(it);
        serverbound_recap_iterators_sorted_size.push_back(it);
    }
    std::sort(serverbound_recap_iterators_sorted_count.begin(), serverbound_recap_iterators_sorted_count.end(),
        [](const map_it& a, const map_it& b)
        {
            return a->second.count > b->second.count;
        });
    std::sort(serverbound_recap_iterators_sorted_size.begin(), serverbound_recap_iterators_sorted_size.end(),
        [](const map_it& a, const map_it& b)
        {
            return a->second.bandwidth_bytes > b->second.bandwidth_bytes;
        });

    std::stringstream output;
    if (max_entry > -1)
    {
        output << "Top " << max_entry << ", sorted by count:\n";
    }
    else
    {
        output << "Sorted by count:\n";
    }
    output << ReportTable(clientbound_total_network_recap, serverbound_total_network_recap, clientbound_recap_iterators_sorted_count, serverbound_recap_iterators_sorted_count, max_entry, max_name_size);
    output << "\n\n";
    if (max_entry > -1)
    {
        output << "Top " << max_entry << ", sorted by bandwidth:\n";
    }
    else
    {
        output << "Sorted by bandwidth:\n";
    }
    output << ReportTable(clientbound_total_network_recap, serverbound_total_network_recap, clientbound_recap_iterators_sorted_size, serverbound_recap_iterators_sorted_size, max_entry, max_name_size);

    return output.str();
}
