#include "sniffcraft/conf.hpp"
#include "sniffcraft/Compression.hpp"
#include "sniffcraft/Logger.hpp"
#include "sniffcraft/PacketUtilities.hpp"

#include <cmath>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>

#include <protocolCraft/Handler.hpp>
#include <protocolCraft/PacketFactory.hpp>

#ifdef WITH_GUI
#include <imgui.h>
#include <misc/cpp/imgui_stdlib.h>
#endif

using namespace ProtocolCraft;

Logger::Logger()
{
    start_time = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(start_time);

    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d-%H-%M-%S");
    base_filename = ss.str();

    last_time_checked_conf_file = 0;
    last_time_conf_file_loaded = 0;
    last_time_network_recap_printed = 0;

    LoadConfig();

    is_running = true;
    log_thread = std::thread(&Logger::LogConsume, this);
}

#ifdef WITH_GUI
Logger::Logger(const std::filesystem::path& path)
{
    base_filename = path.stem().string();
    is_running = false;
    last_time_checked_conf_file = 0;
    last_time_conf_file_loaded = 0;
    last_time_network_recap_printed = 0;

    std::ifstream file(path, std::ios::in | std::ios::binary);
    file.unsetf(std::ios::skipws);
    std::vector<unsigned char> data((std::istream_iterator<char>(file)), std::istream_iterator<char>());
    file.close();

    ReadIterator iter = data.cbegin();
    size_t length = data.size();

    int protocol_version = ReadData<VarInt>(iter, length);
    if (protocol_version != PROTOCOL_VERSION)
    {
        std::cerr << "Trying to open a capture for protocol version " << protocol_version << " but this version of sniffcraft is compiled for: " << PROTOCOL_VERSION << std::endl;
        throw std::runtime_error("Trying to open a capture file with wrong protocol version");
    }
    start_time = std::chrono::system_clock::time_point(std::chrono::milliseconds(ReadData<VarLong>(iter, length)));

    while (length > 0)
    {
        std::scoped_lock lock(packets_history_mutex, network_recap_mutex);
        LogItem item;
        const bool compressed = ReadData<bool>(iter, length);
        const size_t data_size = ReadData<VarInt>(iter, length);
        ReadIterator packet_iter = iter;
        size_t remaining_size = data_size;
        std::vector<unsigned char> decompressed;
        if (compressed)
        {
            decompressed = Decompress(&(*iter), data_size);
            packet_iter = decompressed.begin();
            remaining_size = decompressed.size();
        }
        item.connection_state = static_cast<ConnectionState>(static_cast<int>(ReadData<VarInt>(packet_iter, remaining_size)));
        item.origin = static_cast<Endpoint>(static_cast<int>(ReadData<VarInt>(packet_iter, remaining_size)));
        item.date = start_time + std::chrono::milliseconds(ReadData<VarLong>(packet_iter, remaining_size));
        item.bandwidth_bytes = static_cast<size_t>(ReadData<VarLong>(packet_iter, remaining_size));
        int packet_id = ReadData<VarInt>(packet_iter, remaining_size);
        const Endpoint origin = SimpleOrigin(item.origin);
        item.packet = origin == Endpoint::Server ? CreateClientboundPacket(item.connection_state, packet_id) : CreateServerboundPacket(item.connection_state, packet_id);
        if (item.packet == nullptr)
        {
            std::cerr << "Error loading the binary file. This might be a bug, please report it. Stopping loading here" << std::endl;
            break;
        }
        item.packet->Read(packet_iter, remaining_size);
        if (item.bandwidth_bytes != 0)
        {
            // Update the recaps
            const std::string packet_name = GetPacketName(item);
            std::map<std::string, NetworkRecapItem>& recap_data_map = (origin == Endpoint::Server ? clientbound_network_recap_data : serverbound_network_recap_data);
            NetworkRecapItem& recap = recap_data_map[packet_name];
            recap.count += 1;
            recap.bandwidth_bytes += item.bandwidth_bytes;
            NetworkRecapItem& total_recap = (origin == Endpoint::Server ? clientbound_total_network_recap : serverbound_total_network_recap);
            total_recap.count += 1;
            total_recap.bandwidth_bytes += item.bandwidth_bytes;
        }
        // Add this item to the packet history
        packets_history.push_back(std::move(item));

        length -= data_size;
        iter += data_size;
    }

    data.clear();

    LoadConfig();
}
#endif

Logger::~Logger()
{
    is_running = false;
    log_condition.notify_all();

    while (!logging_queue.empty())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    if (log_to_file)
    {
        log_file << GenerateNetworkRecap() << std::endl;
    }
    if (log_file.is_open())
    {
        log_file.close();
    }

    if (binary_file.is_open())
    {
        binary_file.close();
    }

    if (log_thread.joinable())
    {
        log_thread.join();
    }
}

void Logger::Log(const std::shared_ptr<Packet>& packet, const ConnectionState connection_state, const Endpoint origin, const size_t bandwidth_bytes)
{
    std::lock_guard<std::mutex> log_guard(log_mutex);
    bool need_to_create_txt_file = log_to_file && !log_file.is_open();
    bool need_to_create_binary_file = log_to_binary_file && !binary_file.is_open();
    if (need_to_create_txt_file || need_to_create_binary_file)
    {
        if (need_to_create_txt_file)
        {
            log_file = std::ofstream(base_filename + "_sclogs.txt", std::ios::out);
        }

        if (need_to_create_binary_file)
        {
            binary_file = std::ofstream(base_filename + ".scbin", std::ios::out|std::ios::binary);
            std::vector<unsigned char> header;
            WriteData<VarInt>(PROTOCOL_VERSION, header);
            WriteData<VarLong>(static_cast<long long int>(std::chrono::duration_cast<std::chrono::milliseconds>(start_time.time_since_epoch()).count()), header);
            binary_file.write(reinterpret_cast<const char*>(header.data()), header.size());
        }
    }

    logging_queue.push({ packet, std::chrono::system_clock::now(), connection_state, origin, bandwidth_bytes });
    log_condition.notify_all();
}

const std::string& Logger::GetBaseFilename() const
{
    return base_filename;
}

void Logger::Stop()
{
    is_running = false;
    log_condition.notify_all();
}

#ifdef WITH_GUI
// Half-transparent orange-ish
static constexpr ImU32 highlight_color = 2147516671;

/// @brief Given a (potentially) detailed Json, will render it recursively
/// @param json Json to render
/// @param start_offset Offset to the end of the data of the start of the current json
/// @param end_offset Offset to the next byte to the end the current json
/// @param indent_level Indent level of rendering for the current json
/// @return First element is a bool indicating if an element of the json is hovered, second element is a pair of offset for the hovered element
std::pair<bool, std::pair<size_t, size_t>> RenderJson(const Json::Value& json, const size_t start_offset, const size_t end_offset, const int indent_level = 0);

/// @brief Remove bytes offset details from json representation
/// @param val Detailed (or not) json representation
/// @return Filtered json representation
Json::Value RemoveParsingDetails(const Json::Value& val);

/// @brief Find the most detailed json path possible of a given byte
/// @param json Detailed json representation
/// @param byte_offset Offset of the byte to find
/// @return A json path as a string
std::string GetJsonPath(const Json::Value& json, const size_t byte_offset);

void RenderNetworkData(const std::map<std::string, NetworkRecapItem>& data, const NetworkRecapItem& total, const float width, const std::string& table_title, const float running_time_s, bool& display_bandwidth_per_s, bool& display_count_per_s);

char ToLowerCase(const char c);

std::string ToLowerCase(const std::string& s);

bool PacketNameMatch(const std::string_view& packet_name, const std::string& search_str_lowcase);

std::tuple<std::shared_ptr<Packet>, ConnectionState, Endpoint> Logger::Render()
{
    ImGuiStyle& style = ImGui::GetStyle();
    std::tuple<std::shared_ptr<Packet>, ConnectionState, Endpoint> return_value = { nullptr, ConnectionState::None, Endpoint::Client };
    ImGui::PushID(base_filename.c_str());
    const ImVec2 available_space = ImGui::GetContentRegionAvail();
    const float min_table_content_width =
        ImGui::CalcTextSize("0000000000").x +
        8 * ImGui::CalcTextSize("00").x +
        ImGui::CalcTextSize("00000000").x +
        ImGui::GetStyle().CellPadding.x * 20 +
        9.0f /* needed, why ? Size of the borders ? */;
    const float table_width = std::min(0.3f * (available_space.x - 2.0f * ImGui::GetStyle().ItemSpacing.x), min_table_content_width + 2.0f * ImGui::GetStyle().FramePadding.x + ImGui::GetStyle().ScrollbarSize);
    if (ImGui::BeginChild("##packet_names_group", ImVec2(0.55f * (available_space.x - 2.0 * ImGui::GetStyle().ItemSpacing.x - table_width), 0.55f * (available_space.y - ImGui::GetStyle().ItemSpacing.y)), ImGuiChildFlags_None, ImGuiWindowFlags_NoBackground))
    {
        ImGui::SetNextItemWidth(
            ImGui::GetContentRegionAvail().x
            - style.ItemSpacing.x
            - ImGui::GetFrameHeight()
            - style.FramePadding.x
            - style.ItemInnerSpacing.x
            - ImGui::CalcTextSize("Include ignored in search").x);
        bool search_changed = false;
        {
            std::scoped_lock<std::mutex> search_lock(search_mutex);
            if (ImGui::InputTextWithHint("##search_packets", "Search packet name...", &search_str))
            {
                search_changed = true;
            }
            ImGui::SameLine();
            if (ImGui::Checkbox("Include ignored in search", &search_ignored_packets))
            {
                search_changed = true;
            }
        }
        if (search_changed)
        {
            UpdateFilteredPackets();
        }

        if (ImGui::BeginChild("##packet_names", ImVec2(0,0), ImGuiChildFlags_FrameStyle, ImGuiWindowFlags_HorizontalScrollbar))
        {
            std::scoped_lock lock(packets_history_mutex);
            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(packets_history_filtered_indices.size()), ImGui::GetTextLineHeightWithSpacing());
            while (clipper.Step())
            {
                for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i)
                {
                    ImGui::PushID(i);
                    const LogItem& item = packets_history[packets_history_filtered_indices[i]];

                    ImGui::SetNextItemAllowOverlap();
                    if (ImGui::Selectable(("##" + std::to_string(i)).c_str(), selected_index == packets_history_filtered_indices[i], ImGuiSelectableFlags_None, ImVec2(0.0f, ImGui::GetTextLineHeightWithSpacing())))
                    {
                        // Select if not selected, deselect if already selected
                        selected_index = packets_history_filtered_indices[i] == selected_index ? -1 : packets_history_filtered_indices[i];
                        if (selected_index != -1)
                        {
                            // We need to dump the message to get the bytes
                            // As fields with non-guaranteed order (e.g. maps)
                            // might have changed, we need to reparse the bytes
                            // (otherwise some offset in the json could match a
                            // different dumped byte)
                            selected_bytes.clear();
                            item.packet->Write(selected_bytes);
                            size_t remaining_bytes = selected_bytes.size();
                            ReadIterator iter = selected_bytes.cbegin();
                            // Skip message ID
                            ReadData<VarInt>(iter, remaining_bytes);
                            std::shared_ptr<Packet> cloned = item.packet->CopyTypeOnly();
                            cloned->Read(iter, remaining_bytes);
                            selected_json = cloned->Serialize();
                        }
                    }
                    if (ImGui::IsItemHovered() && ImGui::BeginTooltip())
                    {
                        ImGui::Text("ID: %i", item.packet->GetId());
                        ImGui::EndTooltip();
                    }
                    ImGui::SameLine();
                    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 0));;
                    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 0));;
                    if (ImGui::Button("X", ImVec2(0.0f, ImGui::GetTextLineHeightWithSpacing())))
                    {
                        return_value = { item.packet, item.connection_state, SimpleOrigin(item.origin) };
                        if (selected_index == packets_history_filtered_indices[i])
                        {
                            selected_index = -1;
                        }
                    }
                    ImGui::PopStyleVar();
                    ImGui::PopStyleVar();
                    if (ImGui::IsItemHovered() && ImGui::BeginTooltip())
                    {
                        ImGui::TextUnformatted("Add to ignore list");
                        ImGui::EndTooltip();
                    }
                    ImGui::SameLine();
                    const std::chrono::system_clock::duration diff = item.date - start_time;
                    auto hours = std::chrono::duration_cast<std::chrono::hours>(diff).count();
                    auto min = std::chrono::duration_cast<std::chrono::minutes>(diff).count();
                    auto sec = std::chrono::duration_cast<std::chrono::seconds>(diff).count();
                    auto millisec = std::chrono::duration_cast<std::chrono::milliseconds>(diff).count();

                    millisec -= sec * 1000;
                    sec -= min * 60;
                    min -= hours * 60;

                    ImGui::Text("[%ld:%02ld:%02ld:%03ld]", hours, min, sec, millisec);
                    ImGui::SameLine();
                    ImGui::Text("[%ld]", packets_history_filtered_indices[i]);
                    ImGui::SameLine();
                    ImGui::TextUnformatted(ConnectionStateToString(item.connection_state).data());
                    ImGui::SameLine();
                    ImGui::TextUnformatted(OriginToString(item.origin).data());
                    ImGui::SameLine();
                    ImGui::TextUnformatted(GetPacketName(item).c_str());
                    ImGui::PopID();
                }
            }
            clipper.End();
            if (selected_index == -1)
            {
                ImGui::SetScrollHereY();
            }
        }
        ImGui::EndChild();
    }
    ImGui::EndChild();

    std::pair<bool, std::pair<size_t, size_t>> hovered_bytes = { false, { 0, 0 } };
    ImGui::SameLine();
    ImGui::BeginChild("##json_display", ImVec2(0.45f * (available_space.x - 2.0 * ImGui::GetStyle().ItemSpacing.x - table_width), 0.55f * (available_space.y - ImGui::GetStyle().ItemSpacing.y)), ImGuiChildFlags_FrameStyle, ImGuiWindowFlags_HorizontalScrollbar);
    if (selected_index != -1)
    {
        hovered_bytes = RenderJson(selected_json, selected_bytes.size(), 0, 0);
        ImGui::SetCursorPosX(ImGui::GetWindowWidth() - ImGui::CalcTextSize("Copy").x - ImGui::GetStyle().FramePadding.x * 3 - ImGui::GetStyle().ScrollbarSize + ImGui::GetScrollX());
        ImGui::SetCursorPosY(ImGui::GetStyle().FramePadding.y + ImGui::GetScrollY());
        if (ImGui::Button("Copy"))
        {
            ImGui::SetClipboardText(RemoveParsingDetails(selected_json).Dump(4).c_str());
        }
    }
    ImGui::EndChild();

    ImGui::SameLine();
    ImGui::BeginChild("##bytes_display", ImVec2(table_width, 0.55f * (available_space.y - ImGui::GetStyle().ItemSpacing.y)), ImGuiChildFlags_FrameStyle, ImGuiWindowFlags_HorizontalScrollbar);
    if (selected_index != -1)
    {
        if (ImGui::BeginTable(
            "##bytes_table",
            10,
            ImGuiTableFlags_RowBg |
            ImGuiTableFlags_BordersOuter |
            ImGuiTableFlags_BordersInnerV |
            ImGuiTableFlags_NoClip,
            ImVec2(min_table_content_width, 0.0f)
        ))
        {
            ImGui::TableSetupColumn("##row_index", ImGuiTableColumnFlags_WidthFixed, ImGui::CalcTextSize("0000000000").x);
            for (int col = 1; col < 9; ++col)
            {
                ImGui::TableSetupColumn(("##byte_" + std::to_string(col)).c_str(), ImGuiTableColumnFlags_WidthFixed, ImGui::CalcTextSize("00").x);
            }
            ImGui::TableSetupColumn("##string_representation", ImGuiTableColumnFlags_WidthFixed, ImGui::CalcTextSize("00000000").x);

            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(std::ceil(static_cast<double>(selected_bytes.size()) / 8.0)));
            while (clipper.Step())
            {
                for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row)
                {
                    ImGui::TableNextRow();
                    for (int column = 0; column < 10; column++)
                    {
                        ImGui::TableSetColumnIndex(column);
                        if (column == 0)
                        {
                            ImGui::Text("%010s", std::to_string(row * 8).c_str());
                        }
                        else if (column == 9)
                        {
                            ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.0f, 0.0f));
                            std::string str_repr = ".";
                            for (size_t i = 0; i < 8; ++i)
                            {
                                const size_t index = row * 8 + i;
                                const size_t index_offset = selected_bytes.size() - index;
                                if (index < selected_bytes.size())
                                {
                                    str_repr[0] = std::isprint(selected_bytes[index]) ? static_cast<char>(selected_bytes[index]) : '.';
                                    ImGui::TextUnformatted(str_repr.c_str());
                                    if (hovered_bytes.first &&
                                        index_offset <= hovered_bytes.second.first &&
                                        index_offset > hovered_bytes.second.second)
                                    {
                                        ImDrawList* draw_list = ImGui::GetWindowDrawList();
                                        ImVec2 p_min = ImGui::GetItemRectMin();
                                        ImVec2 p_max = ImGui::GetItemRectMax();
                                        draw_list->ChannelsSplit(2);
                                        draw_list->ChannelsSetCurrent(0);
                                        draw_list->AddRectFilled(p_min, p_max, highlight_color);
                                        draw_list->ChannelsMerge();
                                    }
                                    if (i < 7)
                                    {
                                        ImGui::SameLine();
                                    }
                                }
                            }
                            ImGui::PopStyleVar();
                        }
                        else
                        {
                            const size_t index = row * 8 + column - 1;
                            const size_t index_offset = selected_bytes.size() - index;
                            if (index < selected_bytes.size())
                            {
                                ImGui::Text("%02X", static_cast<int>(selected_bytes[index]));
                                if (ImGui::IsItemHovered())
                                {
                                    const std::string tooltip = GetJsonPath(selected_json, index_offset);
                                    if (!tooltip.empty())
                                    {
                                        ImGui::SetTooltip(tooltip.c_str());
                                    }
                                }
                            }
                            if (hovered_bytes.first &&
                                index_offset <= hovered_bytes.second.first &&
                                index_offset > hovered_bytes.second.second)
                            {
                                ImGui::TableSetBgColor(ImGuiTableBgTarget_CellBg, highlight_color);
                            }
                        }
                    }
                }
            }
            clipper.End();
            ImGui::EndTable();
            // If hovered with parsed detailed data, scroll to the corresponding row
            if (hovered_bytes.first && hovered_bytes.second.first != 0)
            {
                ImGui::SetScrollY(clipper.ItemsHeight * std::floor(static_cast<float>(selected_bytes.size() - hovered_bytes.second.first) / 8.0f));
            }
        }
    }
    ImGui::EndChild();

    {
        std::scoped_lock<std::mutex> lock(network_recap_mutex);
        const float running_s =
            is_running ?
            static_cast<float>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - start_time).count()) / 1000.0f :
            packets_history.empty() ?
                1.0f :
                static_cast<float>(std::chrono::duration_cast<std::chrono::milliseconds>(packets_history.back().date - start_time).count()) / 1000.0f;
        RenderNetworkData(clientbound_network_recap_data, clientbound_total_network_recap, 0.5f * (available_space.x - ImGui::GetStyle().ItemSpacing.x), "Server --> Client", running_s, bandwidth_per_s_clientbound, count_per_s_clientbound);
        ImGui::SameLine();
        RenderNetworkData(serverbound_network_recap_data, serverbound_total_network_recap, 0.5f * (available_space.x - ImGui::GetStyle().ItemSpacing.x), "Client --> Server", running_s, bandwidth_per_s_serverbound, count_per_s_serverbound);
    }

    ImGui::PopID();
    return return_value;
}

void Logger::UpdateFilteredPackets()
{
    std::scoped_lock locks(packets_history_mutex, search_mutex, ignored_packets_mutex);
    packets_history_filtered_indices.clear();
    // No search string, just hide all ignored packets
    if (search_str.empty())
    {
        for (size_t i = 0; i < packets_history.size(); ++i)
        {
            const std::set<int>& ignored_set = ignored_packets[{packets_history[i].connection_state, SimpleOrigin(packets_history[i].origin)}];
            const bool is_ignored = ignored_set.find(packets_history[i].packet->GetId()) != ignored_set.end();
            if (!is_ignored)
            {
                packets_history_filtered_indices.push_back(i);
            }
        }
    }
    // Else check for each packet if it matches with the search query
    else
    {
        const std::string lower_case_search = ToLowerCase(search_str);
        for (size_t i = 0; i < packets_history.size(); ++i)
        {
            const LogItem& item = packets_history[i];
            const std::set<int>& ignored_set = ignored_packets[{item.connection_state, SimpleOrigin(item.origin)}];
            const bool is_ignored = ignored_set.find(item.packet->GetId()) != ignored_set.end();
            if (is_ignored && !search_ignored_packets)
            {
                continue;
            }
            if (PacketNameMatch(item.packet->GetName(), lower_case_search))
            {
                packets_history_filtered_indices.push_back(i);
            }
        }
    }
}
#endif

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

            if (item.packet == nullptr)
            {
                output
                    << '['
                    << hours
                    << ':'
                    << std::setw(2) << std::setfill('0') << min
                    << ':'
                    << std::setw(2) << std::setfill('0') << sec
                    << ':'
                    << std::setw(3) << std::setfill('0') << millisec
                    << "] "
                    << ConnectionStateToString(item.connection_state) << ' '
                    << OriginToString(item.origin) << ' ';
                output << "UNKNOWN OR WRONGLY PARSED MESSAGE";
                const std::string output_str = output.str();
                if (log_to_file)
                {
                    log_file << output_str << std::endl;
                }
                if (log_to_console)
                {
                    std::cout << output_str << std::endl;
                }
                continue;
            }

            const std::string packet_name = GetPacketName(item);

            // Update network recap data
            if (item.bandwidth_bytes > 0)
            {
                std::scoped_lock lock(network_recap_mutex);
                const Endpoint simple_origin = SimpleOrigin(item.origin);
                std::map<std::string, NetworkRecapItem>& recap_data_map = simple_origin == Endpoint::Server ? clientbound_network_recap_data : serverbound_network_recap_data;

                NetworkRecapItem& recap = recap_data_map[packet_name];
                recap.count += 1;
                recap.bandwidth_bytes += item.bandwidth_bytes;

                NetworkRecapItem& total_recap_item = simple_origin == Endpoint::Server ? clientbound_total_network_recap : serverbound_total_network_recap;
                total_recap_item.count += 1;
                total_recap_item.bandwidth_bytes += item.bandwidth_bytes;
            }

            if (log_to_binary_file)
            {
                std::vector<unsigned char> serialized;
                WriteData<VarInt>(static_cast<int>(item.connection_state), serialized);
                WriteData<VarInt>(static_cast<int>(item.origin), serialized);
                const long long int time_since_epoch = std::chrono::system_clock::to_time_t(item.date);
                WriteData<VarLong>(static_cast<long long int>(std::chrono::duration_cast<std::chrono::milliseconds>(item.date - start_time).count()), serialized);
                WriteData<VarLong>(static_cast<long long int>(item.bandwidth_bytes), serialized);
                item.packet->Write(serialized);
                std::vector<unsigned char> serialized_header;
                WriteData<bool>(serialized.size() > 256, serialized_header);
                if (serialized.size() > 256)
                {
                    serialized = Compress(serialized);
                }
                WriteData<VarInt>(static_cast<int>(serialized.size()), serialized_header);
                binary_file.write(reinterpret_cast<const char*>(serialized_header.data()), serialized_header.size());
                binary_file.write(reinterpret_cast<const char*>(serialized.data()), serialized.size());
            }

#ifdef WITH_GUI
            if (in_gui)
            {
                std::scoped_lock<std::mutex> archive_lock(packets_history_mutex);
                packets_history.push_back(item);
            }
#endif

            {
                std::scoped_lock lock(ignored_packets_mutex);
                const std::set<int>& ignored_set = ignored_packets[{item.connection_state, SimpleOrigin(item.origin)}];
                const bool is_ignored = ignored_set.find(item.packet->GetId()) != ignored_set.end();
#ifdef WITH_GUI
                // If this packet is ignored but we have an active filter on ignored packet, add it to display
                if (in_gui)
                {
                    std::scoped_lock<std::mutex> search_lock(search_mutex);
                    if (is_ignored &&
                        search_ignored_packets &&
                        !search_str.empty() &&
                        PacketNameMatch(item.packet->GetName(), ToLowerCase(search_str))
                    )
                    {
                        std::scoped_lock<std::mutex> history_lock(packets_history_mutex);
                        packets_history_filtered_indices.push_back(packets_history.size() - 1);
                    }
                }
#endif
                if (is_ignored)
                {
                    continue;
                }
            }

#ifdef WITH_GUI
            if (in_gui)
            {
                std::scoped_lock<std::mutex, std::mutex> history_lock(packets_history_mutex, search_mutex);
                if (search_str.empty() || PacketNameMatch(item.packet->GetName(), ToLowerCase(search_str)))
                {
                    packets_history_filtered_indices.push_back(packets_history.size() - 1);
                }
            }
#endif

            const std::set<int>& detailed_set = detailed_packets[{item.connection_state, SimpleOrigin(item.origin)}];
            const bool is_detailed = detailed_set.find(item.packet->GetId()) != detailed_set.end();

            output
                << '['
                << hours
                << ':'
                << std::setw(2) << std::setfill('0') << min
                << ':'
                << std::setw(2) << std::setfill('0') << sec
                << ':'
                << std::setw(3) << std::setfill('0') << millisec
                << "] "
                << ConnectionStateToString(item.connection_state) << ' '
                << OriginToString(item.origin) << ' ';
            output << packet_name;
            if (log_raw_bytes)
            {
                output << '\n';
                std::vector<unsigned char> bytes;
                item.packet->Write(bytes);
                for (size_t i = 0; i < bytes.size(); ++i)
                {
                    output << "0x" << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(bytes[i]) << (i == bytes.size() - 1 ? "" : " ");
                }
            }
            if (is_detailed)
            {
#ifdef WITH_GUI
                output << "\n" << RemoveParsingDetails(item.packet->Serialize()).Dump(4);
#else
                output << "\n" << item.packet->Serialize().Dump(4);
#endif
            }

            const std::string output_str = output.str();
            if (log_to_file)
            {
                log_file << output_str << std::endl;
            }
            if (log_to_console)
            {
                std::cout << output_str << std::endl;
            }

            // Every 5 seconds, check if the conf file has changed and reload it if needed
            std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            if (now - last_time_checked_conf_file > 5)
            {
                last_time_checked_conf_file = now;
                LoadConfig();
            }

            // Every 10 seconds, print network recap if option is true
            if (log_network_recap_console && now - last_time_network_recap_printed > 10)
            {
                last_time_network_recap_printed = now;
                std::cout << GenerateNetworkRecap(10, 18) << std::endl;
            }
        }
    }

    if (log_file.is_open())
    {
        log_file.close();
    }
    if (binary_file.is_open())
    {
        binary_file.close();
    }
}

void Logger::LoadConfig()
{
    std::time_t modification_time = Conf::GetModifiedTimestamp();
    if (modification_time == -1 ||
        modification_time == last_time_conf_file_loaded)
    {
        return;
    }

    std::cout << "Loading updated conf file..." << std::endl;

    Json::Value conf;
    {
        std::shared_lock<std::shared_mutex> lock(Conf::conf_mutex);
        last_time_conf_file_loaded = Conf::GetModifiedTimestamp();
        conf = Conf::LoadConf();
    }

    const std::map<std::string, ConnectionState> name_mapping = {
        { Conf::handshaking_key, ConnectionState::Handshake },
        { Conf::status_key, ConnectionState::Status },
        { Conf::login_key, ConnectionState::Login },
        { Conf::play_key, ConnectionState::Play },
#if PROTOCOL_VERSION > 763 /* > 1.20.1 */
        { Conf::configuration_key, ConnectionState::Configuration },
#endif
    };

    log_to_file = !conf.contains(Conf::text_file_log_key) || conf[Conf::text_file_log_key].get<bool>();
    log_to_console = conf.contains(Conf::console_log_key) && conf[Conf::console_log_key].get<bool>();
    log_network_recap_console = conf.contains(Conf::network_recap_to_console_key) && conf[Conf::network_recap_to_console_key].get<bool>();
    log_raw_bytes = conf.contains(Conf::raw_bytes_log_key) && conf[Conf::raw_bytes_log_key].get<bool>();
    log_to_binary_file = conf.contains(Conf::binary_file_log_key) && conf[Conf::binary_file_log_key].get<bool>();
#ifdef WITH_GUI
    in_gui = !Conf::headless;
#endif

    {
        std::scoped_lock lock(ignored_packets_mutex);
        for (auto it = name_mapping.begin(); it != name_mapping.end(); ++it)
        {
            if (conf.contains(it->first))
            {
                LoadPacketsFromJson(conf[it->first], it->second);
            }
            else
            {
                LoadPacketsFromJson(Json::Value(), it->second);
            }
        }
    }

#ifdef WITH_GUI
    // Rewrite filtered packet history with updated ignored lists
    if (in_gui)
    {
        UpdateFilteredPackets();
    }
#endif
    std::cout << "Conf file loaded from " << Conf::conf_path << std::endl;
}

int GetIdFromName(const std::string& name, const ConnectionState connection_state, const bool clientbound)
{
    if (clientbound)
    {
        switch (connection_state)
        {
        case ConnectionState::None:
            return -1;
        case ConnectionState::Handshake:
            return -1;
        case ConnectionState::Status:
            for (const auto& s : PacketNameIdExtractor<AllClientboundStatusPackets>::name_ids)
            {
                if (s.name == name)
                {
                    return s.id;
                }
            }
            return -1;
        case ConnectionState::Login:
            for (const auto& s : PacketNameIdExtractor<AllClientboundLoginPackets>::name_ids)
            {
                if (s.name == name)
                {
                    return s.id;
                }
            }
            return -1;
        case ConnectionState::Play:
            for (const auto& s : PacketNameIdExtractor<AllClientboundPlayPackets>::name_ids)
            {
                if (s.name == name)
                {
                    return s.id;
                }
            }
            return -1;
#if PROTOCOL_VERSION > 763 /* > 1.20.1 */
        case ConnectionState::Configuration:
            for (const auto& s : PacketNameIdExtractor<AllClientboundConfigurationPackets>::name_ids)
            {
                if (s.name == name)
                {
                    return s.id;
                }
            }
            return -1;
#endif
        }
    }
    else
    {
        switch (connection_state)
        {
        case ConnectionState::None:
            return -1;
        case ConnectionState::Handshake:
            for (const auto& s : PacketNameIdExtractor<AllServerboundHandshakingPackets>::name_ids)
            {
                if (s.name == name)
                {
                    return s.id;
                }
            }
            return -1;
        case ConnectionState::Status:
            for (const auto& s : PacketNameIdExtractor<AllServerboundStatusPackets>::name_ids)
            {
                if (s.name == name)
                {
                    return s.id;
                }
            }
            return -1;
        case ConnectionState::Login:
            for (const auto& s : PacketNameIdExtractor<AllServerboundLoginPackets>::name_ids)
            {
                if (s.name == name)
                {
                    return s.id;
                }
            }
            return -1;
        case ConnectionState::Play:
            for (const auto& s : PacketNameIdExtractor<AllServerboundPlayPackets>::name_ids)
            {
                if (s.name == name)
                {
                    return s.id;
                }
            }
            return -1;
#if PROTOCOL_VERSION > 763 /* > 1.20.1 */
        case ConnectionState::Configuration:
            for (const auto& s : PacketNameIdExtractor<AllServerboundConfigurationPackets>::name_ids)
            {
                if (s.name == name)
                {
                    return s.id;
                }
            }
            return -1;
#endif
        }
    }
    return -1;
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

    if (value.contains(Conf::ignored_clientbound_key) && value[Conf::ignored_clientbound_key].is_array())
    {
        for (const auto& val : value[Conf::ignored_clientbound_key].get_array())
        {
            if (val.is_number())
            {
                ignored_packets[{connection_state, Endpoint::Server}].insert(val.get<int>());
            }
            else if (val.is_string())
            {
                const int packet_id = GetIdFromName(val.get<std::string>(), connection_state, true);
                if (packet_id > -1)
                {
                    ignored_packets[{connection_state, Endpoint::Server}].insert(packet_id);
                }
            }
        }
    }

    if (value.contains(Conf::ignored_serverbound_key) && value[Conf::ignored_serverbound_key].is_array())
    {
        for (const auto& val : value[Conf::ignored_serverbound_key].get_array())
        {
            if (val.is_number())
            {
                ignored_packets[{connection_state, Endpoint::Client}].insert(val.get<int>());
            }
            else if (val.is_string())
            {
                const int packet_id = GetIdFromName(val.get<std::string>(), connection_state, false);
                if (packet_id > -1)
                {
                    ignored_packets[{connection_state, Endpoint::Client}].insert(packet_id);
                }
            }
        }
    }

    if (value.contains(Conf::detailed_clientbound_key) && value[Conf::detailed_clientbound_key].is_array())
    {
        for (const auto& val : value[Conf::detailed_clientbound_key].get_array())
        {
            if (val.is_number())
            {
                detailed_packets[{connection_state, Endpoint::Server}].insert(val.get<int>());
            }
            else if (val.is_string())
            {
                const int packet_id = GetIdFromName(val.get<std::string>(), connection_state, true);
                if (packet_id > -1)
                {
                    detailed_packets[{connection_state, Endpoint::Server}].insert(packet_id);
                }
            }
        }
    }

    if (value.contains(Conf::detailed_serverbound_key) && value[Conf::detailed_serverbound_key].is_array())
    {
        for (const auto& val : value[Conf::detailed_serverbound_key].get_array())
        {
            if (val.is_number())
            {
                detailed_packets[{connection_state, Endpoint::Client}].insert(val.get<int>());
            }
            else if (val.is_string())
            {
                const int packet_id = GetIdFromName(val.get<std::string>(), connection_state, false);
                if (packet_id > -1)
                {
                    detailed_packets[{connection_state, Endpoint::Client}].insert(packet_id);
                }
            }
        }
    }
}

std::string_view Logger::OriginToString(const Endpoint origin) const
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

std::string_view Logger::ConnectionStateToString(const ConnectionState connection_state) const
{
    switch (connection_state)
    {
    case ConnectionState::None:
        return "[None]";
    case ConnectionState::Handshake:
        return "[Handshake]";
    case ConnectionState::Login:
        return "[Login]";
    case ConnectionState::Status:
        return "[Status]";
    case ConnectionState::Play:
        return "[Play]";
#if PROTOCOL_VERSION > 763 /* > 1.20.1 */
    case ConnectionState::Configuration:
        return "[Configuration]";
#endif
    }
    return "";
}

std::string Logger::GetPacketName(const LogItem& item) const
{
    const Endpoint simple_origin = SimpleOrigin(item.origin);
    const std::string packet_name(item.packet->GetName());
    switch (item.connection_state)
    {
    case ConnectionState::Play:
        if (simple_origin == Endpoint::Server && item.packet->GetId() == Internal::get_tuple_index<ClientboundCustomPayloadPacket, AllClientboundPlayPackets>)
        {
            std::shared_ptr<ClientboundCustomPayloadPacket> custom_payload = std::dynamic_pointer_cast<ClientboundCustomPayloadPacket>(item.packet);
            return packet_name + '|' + custom_payload->GetIdentifier();
        }
        else if (simple_origin == Endpoint::Client && item.packet->GetId() == Internal::get_tuple_index<ServerboundCustomPayloadPacket, AllServerboundPlayPackets>)
        {
            std::shared_ptr<ServerboundCustomPayloadPacket> custom_payload = std::dynamic_pointer_cast<ServerboundCustomPayloadPacket>(item.packet);
            return packet_name + '|' + custom_payload->GetIdentifier();
        }
        break;
#if PROTOCOL_VERSION > 763 /* > 1.20.1 */
    case ConnectionState::Configuration:
        if (simple_origin == Endpoint::Server && item.packet->GetId() == Internal::get_tuple_index<ClientboundCustomPayloadConfigurationPacket, AllClientboundConfigurationPackets>)
        {
            std::shared_ptr<ClientboundCustomPayloadConfigurationPacket> custom_payload = std::dynamic_pointer_cast<ClientboundCustomPayloadConfigurationPacket>(item.packet);
            return packet_name + '|' + custom_payload->GetIdentifier();
        }
        else if (simple_origin == Endpoint::Client && item.packet->GetId() == Internal::get_tuple_index<ServerboundCustomPayloadConfigurationPacket, AllServerboundConfigurationPackets>)
        {
            std::shared_ptr<ServerboundCustomPayloadConfigurationPacket> custom_payload = std::dynamic_pointer_cast<ServerboundCustomPayloadConfigurationPacket>(item.packet);
            return packet_name + '|' + custom_payload->GetIdentifier();
        }
        break;
#endif
#if PROTOCOL_VERSION > 340 /* > 1.12.2 */
    case ConnectionState::Login:
        if (simple_origin == Endpoint::Server && item.packet->GetId() == Internal::get_tuple_index<ClientboundCustomQueryPacket, AllClientboundLoginPackets>)
        {
            std::shared_ptr<ClientboundCustomQueryPacket> custom_payload = std::dynamic_pointer_cast<ClientboundCustomQueryPacket>(item.packet);
            return packet_name + '|' + custom_payload->GetIdentifier().GetFull();
        }
        break;
#endif
    default:
        break;
    }
    return packet_name;
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
            clientbound_max_name_length = static_cast<int>(clientbound_items[i]->first.size());
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
            serverbound_max_name_length = static_cast<int>(serverbound_items[i]->first.size());
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
    std::scoped_lock lock(network_recap_mutex);
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

#ifdef WITH_GUI
std::pair<bool, std::pair<size_t, size_t>> RenderJson(const Json::Value& json, const size_t start_offset, const size_t end_offset, const int indent_level)
{
    std::string indent_string = "";
    for (int i = 0; i < indent_level; ++i)
    {
        indent_string += "  ";
    }

    if (json.is_object() && json.contains("start_offset") && json.contains("end_offset") && json.contains("content"))
    {
        return RenderJson(json["content"], json["start_offset"].get<unsigned long long int>(), json["end_offset"].get<unsigned long long int>(), indent_level);
    }
    else if (json.is_object())
    {
        ImGui::TextUnformatted("{");
        bool object_hovered = ImGui::IsItemHovered();
        std::pair<bool, std::pair<size_t, size_t>> child_return = { false, { start_offset, end_offset} };
        size_t index = 0;
        for (const auto& [k, v] : json.get_object())
        {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.5f, 0.5f, 1.0f));
            ImGui::TextUnformatted((indent_string + "  \"" + k + "\": ").c_str());
            bool child_hovered = ImGui::IsItemHovered();
            ImGui::PopStyleColor();
            ImGui::SameLine(0.0f, 0.0f);
            const std::pair<bool, std::pair<size_t, size_t>> current_child_return = RenderJson(v, start_offset, end_offset, indent_level + 1);
            index += 1;
            if (index < json.size())
            {
                ImGui::SameLine(0.0f, 0.0f);
                ImGui::TextUnformatted(",");
                child_hovered |= ImGui::IsItemHovered();
            }
            if (current_child_return.first || child_hovered)
            {
                child_return.first = true;
                child_return.second = current_child_return.second;
            }
        }
        ImGui::TextUnformatted((indent_string + "}").c_str());
        object_hovered |= ImGui::IsItemHovered();

        if (child_return.first)
        {
            return child_return;
        }
        if (object_hovered)
        {
            return { true, { start_offset, end_offset } };
        }
    }
    else if (json.is_array())
    {
        ImGui::TextUnformatted("[");
        bool object_hovered = ImGui::IsItemHovered();
        std::pair<bool, std::pair<size_t, size_t>> child_return = { false, { start_offset, end_offset} };
        size_t index = 0;
        for (const auto& v : json.get_array())
        {
            ImGui::TextUnformatted((indent_string + "  ").c_str());
            bool child_hovered = ImGui::IsItemHovered();
            ImGui::SameLine(0.0f, 0.0f);
            const std::pair<bool, std::pair<size_t, size_t>> current_child_return = RenderJson(v, start_offset, end_offset, indent_level + 1);
            index += 1;
            if (index < json.size())
            {
                ImGui::SameLine(0.0f, 0.0f);
                ImGui::TextUnformatted(",");
                child_hovered |= ImGui::IsItemHovered();
            }
            if (current_child_return.first || child_hovered)
            {
                child_return.first = true;
                child_return.second = current_child_return.second;
            }
        }
        ImGui::TextUnformatted((indent_string + "]").c_str());
        object_hovered |= ImGui::IsItemHovered();
        if (child_return.first)
        {
            return child_return;
        }
        if (object_hovered)
        {
            return { true, { start_offset, end_offset } };
        }
    }
    else
    {
        if (json.is_null())
        {
            ImGui::TextUnformatted("{ }");
        }
        else if (json.is_string())
        {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.5f, 0.75f, 1.0f, 1.0f));
            ImGui::TextUnformatted(('"' + json.get_string() + '"').c_str());
            ImGui::PopStyleColor();
        }
        else if (json.is<unsigned long long int>())
        {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.75f, 1.0f, 1.0f, 1.0f));
            ImGui::TextUnformatted(std::to_string(json.get_number<unsigned long long int>()).c_str());
            ImGui::PopStyleColor();
        }
        else if (json.is<long long int>())
        {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.75f, 1.0f, 1.0f, 1.0f));
            ImGui::TextUnformatted(std::to_string(json.get_number<long long int>()).c_str());
            ImGui::PopStyleColor();
        }
        else if (json.is_number())
        {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.75f, 1.0f, 1.0f, 1.0f));
            ImGui::TextUnformatted(std::to_string(json.get_number()).c_str());
            ImGui::PopStyleColor();
        }
        else if (json.is_bool())
        {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 0.75f, 1.0f));
            ImGui::TextUnformatted((json.get<bool>() ? "true" : "false"));
            ImGui::PopStyleColor();
        }
        if (ImGui::IsItemHovered())
        {
            return { true, { start_offset, end_offset } };
        }
    }

    return { false, { start_offset, end_offset} };
}

Json::Value RemoveParsingDetails(const Json::Value& val)
{
    if (val.is_array())
    {
        Json::Array output;
        output.reserve(val.size());
        for (const auto& v : val.get_array())
        {
            output.push_back(RemoveParsingDetails(v));
        }
        return output;
    }
    else if (val.is_object())
    {
        if (val.contains("content") && val.contains("start_offset") && val.contains("end_offset"))
        {
            return RemoveParsingDetails(val["content"]);
        }
        else
        {
            Json::Object output;
            for (const auto& [k, v] : val.get_object())
            {
                output[k] = RemoveParsingDetails(v);
            }
            return output;
        }
    }
    else
    {
        return val;
    }
}

std::string GetJsonPath(const Json::Value& json, const size_t byte_offset)
{
    if (json.is_object())
    {
        for (const auto& [k, v] : json.get_object())
        {
            if (v.is_object() &&
                v.contains("start_offset") &&
                v.contains("end_offset") &&
                v.contains("content") &&
                v["start_offset"].get<unsigned long long int>() >= byte_offset &&
                v["end_offset"].get<unsigned long long int>() < byte_offset
                )
            {
                return "." + k + GetJsonPath(v["content"], byte_offset);
            }
        }
    }
    else if (json.is_array())
    {
        for (size_t i = 0; i < json.size(); ++i)
        {
            const Json::Value& e = json[i];
            if (e.is_object() &&
                e.contains("start_offset") &&
                e.contains("end_offset") &&
                e.contains("content") &&
                e["start_offset"].get<unsigned long long int>() >= byte_offset &&
                e["end_offset"].get<unsigned long long int>() < byte_offset
                )
            {
                return "[" + std::to_string(i) + "]" + GetJsonPath(e["content"], byte_offset);
            }
        }
    }
    return "";
}

void RenderNetworkData(const std::map<std::string, NetworkRecapItem>& data, const NetworkRecapItem& total, const float width, const std::string& table_title, const float running_time_s, bool& display_bandwidth_per_s, bool& display_count_per_s)
{
    char buffer_count[30];
    char buffer_bandwidth[30];

    if (ImGui::BeginTable(table_title.c_str(), 3,
        ImGuiTableFlags_Sortable | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter |
        ImGuiTableFlags_BordersV | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SortTristate,
        ImVec2(width, 0.0f))
    )
    {
        ImGui::TableSetupColumn(table_title.c_str(), ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_WidthStretch, 0.0f, 0);
        ImGui::TableSetupColumn("Count   per s", ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_WidthFixed, 0.0f, 1);
        ImGui::TableSetupColumn("Bandwidth   per s", ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_WidthFixed, 0.0f, 2);

        ImGui::TableSetupScrollFreeze(0, 2);
        ImGui::TableHeadersRow();
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 0));
        ImGui::TableSetColumnIndex(1);
        ImGui::SameLine(ImGui::CalcTextSize("Count ").x);
        ImGui::Checkbox("##count_per_s", &display_count_per_s);
        ImGui::TableSetColumnIndex(2);
        ImGui::SameLine(ImGui::CalcTextSize("Bandwidth ").x);
        ImGui::Checkbox("##bandwidth_per_s", &display_bandwidth_per_s);
        ImGui::PopStyleVar();

        // Always display total line first
        ImGui::PushID("total");
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::TextUnformatted("Total");
        ImGui::TableNextColumn();
        if (display_count_per_s)
        {
            std::sprintf(buffer_count, "%.2f (%6.2f%%)", static_cast<float>(total.count) / running_time_s, 100.0f);
        }
        else
        {
            std::sprintf(buffer_count, "%llu (%6.2f%%)", total.count, 100.0f);
        }
        // Right align in the column
        ImGui::Dummy(ImVec2(std::max(0.0f, ImGui::GetColumnWidth() - ImGui::CalcTextSize(buffer_count).x - ImGui::GetStyle().ItemSpacing.x), ImGui::GetTextLineHeightWithSpacing()));
        ImGui::SameLine();
        ImGui::TextUnformatted(buffer_count);
        ImGui::TableNextColumn();
        if (display_bandwidth_per_s)
        {
            std::sprintf(buffer_bandwidth, "%.2f (%6.2f%%)", static_cast<float>(total.bandwidth_bytes) / running_time_s, 100.0f);
        }
        else
        {
            std::sprintf(buffer_bandwidth, "%llu (%6.2f%%)", total.bandwidth_bytes, 100.0f);
        }
        // Right align in the column
        ImGui::Dummy(ImVec2(std::max(0.0f, ImGui::GetColumnWidth() - ImGui::CalcTextSize(buffer_bandwidth).x - ImGui::GetStyle().ItemSpacing.x), ImGui::GetTextLineHeightWithSpacing()));
        ImGui::SameLine();
        ImGui::TextUnformatted(buffer_bandwidth);
        ImGui::PopID();

        // Sort all the other lines
        std::vector<map_it> sorted_iterators;
        sorted_iterators.reserve(data.size());
        for (auto it = data.cbegin(); it != data.cend(); ++it)
        {
            sorted_iterators.push_back(it);
        }
        // Don't check SpecsDirty as new rows could be added/values could be updated
        if (ImGuiTableSortSpecs* specs = ImGui::TableGetSortSpecs())
        {
            // If sort spec array is > 0, sort according to asked column
            if (specs->SpecsCount > 0)
            {
                // Sort on name
                if (specs->Specs[0].ColumnUserID == 0)
                {
                    if (specs->Specs[0].SortDirection == ImGuiSortDirection_Ascending)
                    {
                        std::sort(sorted_iterators.begin(), sorted_iterators.end(), [&](const map_it& a, const map_it& b)
                            {
                                return a->first < b->first;
                            });
                    }
                    else if (specs->Specs[0].SortDirection == ImGuiSortDirection_Descending)
                    {
                        std::sort(sorted_iterators.begin(), sorted_iterators.end(), [&](const map_it& a, const map_it& b)
                            {
                                return a->first > b->first;
                            });
                    }
                }
                // Sort on count
                else if (specs->Specs[0].ColumnUserID == 1)
                {
                    if (specs->Specs[0].SortDirection == ImGuiSortDirection_Ascending)
                    {
                        std::sort(sorted_iterators.begin(), sorted_iterators.end(), [&](const map_it& a, const map_it& b)
                            {
                                return a->second.count < b->second.count;
                            });
                    }
                    else if (specs->Specs[0].SortDirection == ImGuiSortDirection_Descending)
                    {
                        std::sort(sorted_iterators.begin(), sorted_iterators.end(), [&](const map_it& a, const map_it& b)
                            {
                                return a->second.count > b->second.count;
                            });
                    }
                }
                // Sort on bandwidth
                else if (specs->Specs[0].ColumnUserID == 2)
                {
                    if (specs->Specs[0].SortDirection == ImGuiSortDirection_Ascending)
                    {
                        std::sort(sorted_iterators.begin(), sorted_iterators.end(), [&](const map_it& a, const map_it& b)
                            {
                                return a->second.bandwidth_bytes < b->second.bandwidth_bytes;
                            });
                    }
                    else if (specs->Specs[0].SortDirection == ImGuiSortDirection_Descending)
                    {
                        std::sort(sorted_iterators.begin(), sorted_iterators.end(), [&](const map_it& a, const map_it& b)
                            {
                                return a->second.bandwidth_bytes > b->second.bandwidth_bytes;
                            });
                    }
                }
            }
            specs->SpecsDirty = false;
        }

        // Draw the rows
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(sorted_iterators.size()));
        while (clipper.Step())
        {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i)
            {
                const auto& it = sorted_iterators[i];
                ImGui::PushID(it->first.c_str());
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(it->first.c_str());
                if (ImGui::IsItemHovered() && ImGui::CalcTextSize(it->first.c_str()).x > ImGui::GetColumnWidth() && ImGui::BeginTooltip())
                {
                    ImGui::PushTextWrapPos(ImGui::GetFontSize() * 35.0f);
                    ImGui::TextUnformatted(it->first.c_str());
                    ImGui::PopTextWrapPos();
                    ImGui::EndTooltip();
                }
                ImGui::TableNextColumn();
                if (display_count_per_s)
                {
                    std::sprintf(buffer_count, "%.2f (%6.2f%%)", static_cast<float>(it->second.count) / running_time_s, (100.0f * it->second.count) / total.count);
                }
                else
                {
                    std::sprintf(buffer_count, "%llu (%6.2f%%)", it->second.count, (100.0f * it->second.count) / total.count);
                }
                // Right align in the column
                ImGui::Dummy(ImVec2(std::max(0.0f, ImGui::GetColumnWidth() - ImGui::CalcTextSize(buffer_count).x - ImGui::GetStyle().ItemSpacing.x), ImGui::GetTextLineHeightWithSpacing()));
                ImGui::SameLine();
                ImGui::TextUnformatted(buffer_count);
                ImGui::TableNextColumn();
                if (display_bandwidth_per_s)
                {
                    std::sprintf(buffer_bandwidth, "%.2f (%6.2f%%)", static_cast<float>(it->second.bandwidth_bytes) / running_time_s, (100.0f * it->second.bandwidth_bytes) / total.bandwidth_bytes);
                }
                else
                {
                    std::sprintf(buffer_bandwidth, "%llu (%6.2f%%)", it->second.bandwidth_bytes, (100.0f * it->second.bandwidth_bytes) / total.bandwidth_bytes);
                }
                // Right align in the column
                ImGui::Dummy(ImVec2(std::max(0.0f, ImGui::GetColumnWidth() - ImGui::CalcTextSize(buffer_bandwidth).x - ImGui::GetStyle().ItemSpacing.x), ImGui::GetTextLineHeightWithSpacing()));
                ImGui::SameLine();
                ImGui::TextUnformatted(buffer_bandwidth);
                ImGui::PopID();
            }
        }

        ImGui::EndTable();
    }
}

char ToLowerCase(const char c)
{
    return (c >= 'A' && c < 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

std::string ToLowerCase(const std::string& s)
{
    std::string output;
    output.reserve(s.size());
    for (const char c : s)
    {
        output.push_back(ToLowerCase(c));
    }
    return output;
}

bool PacketNameMatch(const std::string_view& packet_name, const std::string& search_str_lowcase)
{
    return std::search(
        packet_name.begin(), packet_name.end(),
        search_str_lowcase.begin(), search_str_lowcase.end(),
        [](const char c1, const char c2) { return ToLowerCase(c1) == c2; }
    ) != packet_name.end();
}
#endif
