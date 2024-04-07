#include "sniffcraft/conf.hpp"
#include "sniffcraft/MinecraftProxy.hpp"
#include "sniffcraft/Logger.hpp"
#include "sniffcraft/PacketUtilities.hpp"
#include "sniffcraft/server.hpp"

#include <botcraft/Network/DNS/DNSMessage.hpp>
#include <botcraft/Network/DNS/DNSSrvData.hpp>
#include <botcraft/Utilities/StringUtilities.hpp>

#include <filesystem>
#include <functional>
#include <fstream>
#include <iostream>
#include <utility>

#ifdef WITH_GUI
#include <imgui.h>
#include <misc/cpp/imgui_stdlib.h>
#include <backends/imgui_impl_glfw.h>
#include <backends/imgui_impl_opengl3.h>
#include <glad/glad.h>
#include <GLFW/glfw3.h>
#endif

Server::Server()
{
    std::shared_lock<std::shared_mutex> conf_lock(Conf::conf_mutex);
    const ProtocolCraft::Json::Value conf = Conf::LoadConf();
    client_port = conf[Conf::local_port_key].get_number<unsigned short>();
    server_address = conf[Conf::server_address_key].get_string();
    ResolveIpPortFromAddress();

    proxies_cleaning_thread = std::thread(&Server::CleanProxies, this);
}

Server::~Server()
{
#ifdef WITH_GUI
    io_context.stop();
    if (iocontext_thread.joinable())
    {
        iocontext_thread.join();
    }
#endif

    if (proxies_cleaning_thread_running)
    {
        proxies_cleaning_thread_running = false;
        proxies_cleaning_thread.join();
    }
}

void Server::run()
{
#ifdef WITH_GUI
    if (Conf::headless)
    {
        run_iocontext();
    }
    else
    {
        Render();
    }
#else
    run_iocontext();
#endif
}

void Server::run_iocontext()
{
    acceptor = std::make_unique<asio::ip::tcp::acceptor>(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), client_port));
    listen_connection();
    std::cout << "Starting redirection of any connection on 127.0.0.1:" << client_port << " to " << server_ip << ":" << server_port << std::endl;
    io_context.run();
}

void Server::listen_connection()
{
    BaseProxy* proxy = GetNewMinecraftProxy();

    acceptor->async_accept(proxy->ClientSocket(),
        std::bind(&Server::handle_accept, this, proxy,
            std::placeholders::_1));
}

void Server::handle_accept(BaseProxy* new_proxy, const asio::error_code& ec)
{
    if (!ec)
    {
        new_proxy->Start(server_ip, server_port);
#ifdef WITH_GUI
        if (MinecraftProxy* casted_proxy = dynamic_cast<MinecraftProxy*>(new_proxy))
        {
            std::scoped_lock<std::mutex> lock(loggers_mutex);
            loggers.push_back(casted_proxy->GetLogger());
        }
#endif
    }
    else
    {
        std::cerr << "Failed to start new proxy" << std::endl;
    }
    listen_connection();
}

void Server::ResolveIpPortFromAddress()
{
    std::string addressOnly;

    const std::vector<std::string> splitted_port = Botcraft::Utilities::SplitString(server_address, ':');
    // address:port format
    if (splitted_port.size() > 1)
    {
        try
        {
            server_port = std::stoi(splitted_port[1]);
            server_ip = splitted_port[0];
            return;
        }
        catch (const std::exception&)
        {
            server_port = 0;
        }
        addressOnly = splitted_port[0];
    }
    // address only format
    else
    {
        addressOnly = server_address;
        server_port = 0;
    }

    // If port is unknown we first try a SRV DNS lookup
    std::cout << "Performing SRV DNS lookup on " << "_minecraft._tcp." << addressOnly << " to find an endpoint" << std::endl;
    asio::ip::udp::socket udp_socket(io_context);

    // Create the query
    Botcraft::DNSMessage query;
    // Random identification
    query.SetIdentification({ 0x42, 0x42 });
    query.SetFlagQR(0);
    query.SetFlagOPCode(0);
    query.SetFlagAA(0);
    query.SetFlagTC(0);
    query.SetFlagRD(1);
    query.SetFlagRA(0);
    query.SetFlagZ(0);
    query.SetFlagRCode(0);
    query.SetNumberQuestion(1);
    query.SetNumberAnswer(0);
    query.SetNumberAuthority(0);
    query.SetNumberAdditionalRR(0);
    Botcraft::DNSQuestion question;
    // SRV type
    question.SetTypeCode(33);
    question.SetClassCode(1);
    question.SetNameLabels(Botcraft::Utilities::SplitString("_minecraft._tcp." + server_address, '.'));
    query.SetQuestions({ question });

    // Write the request and send it to google DNS
    std::vector<unsigned char> encoded_query;
    query.Write(encoded_query);
    udp_socket.open(asio::ip::udp::v4());
    asio::ip::udp::endpoint endpoint(asio::ip::address::from_string("8.8.8.8"), 53);
    udp_socket.send_to(asio::buffer(encoded_query), endpoint);

    // Wait for the answer
    std::vector<unsigned char> answer_buffer(512);
    asio::ip::udp::endpoint sender_endpoint;
    const size_t len = udp_socket.receive_from(asio::buffer(answer_buffer), sender_endpoint);

    ProtocolCraft::ReadIterator iter = answer_buffer.begin();
    size_t remaining = len;

    // Read answer
    Botcraft::DNSMessage answer;
    answer.Read(iter, remaining);

    // If there is an answer and it's a SRV one (as it should be)
    if (answer.GetNumberAnswer() > 0
        && answer.GetAnswers()[0].GetTypeCode() == 0x21)
    {
        Botcraft::DNSSrvData data;
        auto iter2 = answer.GetAnswers()[0].GetRData().begin();
        size_t len2 = answer.GetAnswers()[0].GetRDLength();
        data.Read(iter2, len2);
        server_ip = "";
        for (int i = 0; i < data.GetNameLabels().size(); ++i)
        {
            server_ip += data.GetNameLabels()[i] + (i == data.GetNameLabels().size() - 1 ? "" : ".");
        }
        server_port = data.GetPort();

        std::cout << "SRV DNS lookup successful!" << std::endl;
        return;
    }
    std::cout << "SRV DNS lookup failed to find an address" << std::endl;

    // If we are here either the port was given or the SRV failed 
    // In both cases we need to assume the given address is the correct one
    server_port = (server_port == 0) ? 25565 : server_port;
    server_ip = addressOnly;
}

BaseProxy* Server::GetNewMinecraftProxy()
{
    std::lock_guard<std::mutex> lock(proxies_mutex);
    // Create a new proxy
    std::unique_ptr<BaseProxy> proxy = std::make_unique<MinecraftProxy>(io_context);
    proxies.push_back(std::move(proxy));

    return proxies.back().get();
}

void Server::CleanProxies()
{
    proxies_cleaning_thread_running = true;
    while (proxies_cleaning_thread_running)
    {
        {
            std::lock_guard<std::mutex> lock(proxies_mutex);
            // Clean old proxies
            for (int i = static_cast<int>(proxies.size()) - 1; i > -1; --i)
            {
                if (proxies[i]->Started() && !proxies[i]->Running())
                {
                    proxies.erase(proxies.begin() + i);
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

#ifdef WITH_GUI
void Server::Render()
{
    glfwInit();
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
#ifdef __APPLE__
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
#endif

    glfwWindowHint(GLFW_RESIZABLE, GL_FALSE);
    GLFWwindow* window = glfwCreateWindow(960, 960, "SniffCraft", NULL, NULL);
    if (window == NULL)
    {
        std::cerr << "Failed to create GLFW window" << std::endl;
        glfwTerminate();
        return;
    }

    glfwSetWindowUserPointer(window, this);
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);
    glfwSetInputMode(window, GLFW_CURSOR, GLFW_CURSOR_NORMAL);
    glfwSetDropCallback(window, [](GLFWwindow* w, int count, const char** paths)
        {
            Server* server = static_cast<Server*>(glfwGetWindowUserPointer(w));
            std::scoped_lock lock(server->loggers_mutex);
            for (int i = 0; i < count; ++i)
            {
                try
                {
                    server->loggers.push_back(std::make_shared<Logger>(std::filesystem::path(paths[i])));
                }
                catch (std::runtime_error& e)
                {
                    std::cerr << "Error trying to load binary file: " << e.what() << std::endl;
                }
            }
        });

    // glad: load all OpenGL function pointers
    // ---------------------------------------
    if (!gladLoadGLLoader((GLADloadproc)glfwGetProcAddress))
    {
        std::cerr << "Failed to initialize GLAD" << std::endl;
        return;
    }

    // imgui: setup context
    // ---------------------------------------
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();

    // Style
    ImGui::StyleColorsDark();
    ImGui::GetIO().IniFilename = NULL;
    ImGui::GetIO().LogFilename = NULL;

    // Setup platform/renderer
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 330");

    InternalRenderLoop(window);

    // ImGui cleaning
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();
}

void HelpMarker(const char* tooltip);

void Server::InternalRenderLoop(GLFWwindow* window)
{
    int width, height;
    glfwGetWindowSize(window, &width, &height);

    // A bunch of variables used as display data during one frame
    // App parameters
    bool started = false;
    std::string local_port_str = std::to_string(client_port);
    bool is_online = false;
    std::string cache_key = "";
    bool log_to_console = false;
    bool network_recap_to_console = false;
    bool log_to_text_file = false;
    bool log_to_bin_file = false;
    bool log_raw_bytes = false;
    bool log_to_replay_file = false;

    // Display filter
    const std::vector<std::string> connection_state_str = {
        "Handshake",
        "Status",
        "Login",
        "Play",
#if PROTOCOL_VERSION > 763 /* > 1.20.1 */
        "Configuration"
#endif
    };
    int selected_connection_state = 3;
    const std::vector<std::string> direction_str = {
        "Server --> Client",
        "Client --> Server"
    };
    int selected_direction = 0;
    std::vector<NameID> displayed;
    std::vector<NameID> hidden;

    const auto on_display_changed = [&]()
    {
        std::shared_lock<std::shared_mutex> lock(Conf::conf_mutex);
        const ProtocolCraft::Json::Value conf = Conf::LoadConf();
        const ConnectionState state = static_cast<ConnectionState>(selected_connection_state);
        displayed.clear();
        hidden.clear();
        // Clientbound
        if (selected_direction == 0)
        {
            switch (state)
            {
            case ConnectionState::None:
                return;
            case ConnectionState::Handshake:
                return;
            case ConnectionState::Status:
                for (const auto& s : PacketNameIdExtractor<AllClientboundStatusMessages>::name_ids)
                {
                    bool ignored = false;
                    for (const auto& v : conf[Conf::status_key][Conf::ignored_clientbound_key].get_array())
                    {
                        if ((v.is_number() && v.get_number<int>() == s.id) ||
                            (v.is_string() && v.get_string() == s.name))
                        {
                            ignored = true;
                            break;
                        }
                    }
                    (ignored ? hidden : displayed).push_back(s);
                }
                break;
            case ConnectionState::Login:
                for (const auto& s : PacketNameIdExtractor<AllClientboundLoginMessages>::name_ids)
                {
                    bool ignored = false;
                    for (const auto& v : conf[Conf::login_key][Conf::ignored_clientbound_key].get_array())
                    {
                        if ((v.is_number() && v.get_number<int>() == s.id) ||
                            (v.is_string() && v.get_string() == s.name))
                        {
                            ignored = true;
                            break;
                        }
                    }
                    (ignored ? hidden : displayed).push_back(s);
                }
                break;
            case ConnectionState::Play:
                for (const auto& s : PacketNameIdExtractor<AllClientboundPlayMessages>::name_ids)
                {
                    bool ignored = false;
                    for (const auto& v : conf[Conf::play_key][Conf::ignored_clientbound_key].get_array())
                    {
                        if ((v.is_number() && v.get_number<int>() == s.id) ||
                            (v.is_string() && v.get_string() == s.name))
                        {
                            ignored = true;
                            break;
                        }
                    }
                    (ignored ? hidden : displayed).push_back(s);
                }
                break;
#if PROTOCOL_VERSION > 763 /* > 1.20.1 */
            case ConnectionState::Configuration:
                for (const auto& s : PacketNameIdExtractor<AllClientboundConfigurationMessages>::name_ids)
                {
                    bool ignored = false;
                    for (const auto& v : conf[Conf::configuration_key][Conf::ignored_clientbound_key].get_array())
                    {
                        if ((v.is_number() && v.get_number<int>() == s.id) ||
                            (v.is_string() && v.get_string() == s.name))
                        {
                            ignored = true;
                            break;
                        }
                    }
                    (ignored ? hidden : displayed).push_back(s);
                }
                break;
#endif
            }
        }
        // Serverbound
        else
        {
            switch (state)
            {
            case ConnectionState::None:
                return;
            case ConnectionState::Handshake:
                for (const auto& s : PacketNameIdExtractor<AllServerboundHandshakeMessages>::name_ids)
                {
                    bool ignored = false;
                    for (const auto& v : conf[Conf::handshaking_key][Conf::ignored_serverbound_key].get_array())
                    {
                        if ((v.is_number() && v.get_number<int>() == s.id) ||
                            (v.is_string() && v.get_string() == s.name))
                        {
                            ignored = true;
                            break;
                        }
                    }
                    (ignored ? hidden : displayed).push_back(s);
                }
                break;
            case ConnectionState::Status:
                for (const auto& s : PacketNameIdExtractor<AllServerboundStatusMessages>::name_ids)
                {
                    bool ignored = false;
                    for (const auto& v : conf[Conf::status_key][Conf::ignored_serverbound_key].get_array())
                    {
                        if ((v.is_number() && v.get_number<int>() == s.id) ||
                            (v.is_string() && v.get_string() == s.name))
                        {
                            ignored = true;
                            break;
                        }
                    }
                    (ignored ? hidden : displayed).push_back(s);
                }
                break;
            case ConnectionState::Login:
                for (const auto& s : PacketNameIdExtractor<AllServerboundLoginMessages>::name_ids)
                {
                    bool ignored = false;
                    for (const auto& v : conf[Conf::login_key][Conf::ignored_serverbound_key].get_array())
                    {
                        if ((v.is_number() && v.get_number<int>() == s.id) ||
                            (v.is_string() && v.get_string() == s.name))
                        {
                            ignored = true;
                            break;
                        }
                    }
                    (ignored ? hidden : displayed).push_back(s);
                }
                break;
            case ConnectionState::Play:
                for (const auto& s : PacketNameIdExtractor<AllServerboundPlayMessages>::name_ids)
                {
                    bool ignored = false;
                    for (const auto& v : conf[Conf::play_key][Conf::ignored_serverbound_key].get_array())
                    {
                        if ((v.is_number() && v.get_number<int>() == s.id) ||
                            (v.is_string() && v.get_string() == s.name))
                        {
                            ignored = true;
                            break;
                        }
                    }
                    (ignored ? hidden : displayed).push_back(s);
                }
                break;
#if PROTOCOL_VERSION > 763 /* > 1.20.1 */
            case ConnectionState::Configuration:
                for (const auto& s : PacketNameIdExtractor<AllServerboundConfigurationMessages>::name_ids)
                {
                    bool ignored = false;
                    for (const auto& v : conf[Conf::configuration_key][Conf::ignored_serverbound_key].get_array())
                    {
                        if ((v.is_number() && v.get_number<int>() == s.id) ||
                            (v.is_string() && v.get_string() == s.name))
                        {
                            ignored = true;
                            break;
                        }
                    }
                    (ignored ? hidden : displayed).push_back(s);
                }
                break;
#endif
            }
        }

        std::sort(displayed.begin(), displayed.end(), [](const NameID& a, const NameID& b) { return a.name < b.name; });
        std::sort(hidden.begin(), hidden.end(), [](const NameID& a, const NameID& b) { return a.name < b.name; });
    };
    const auto on_ignored_changed = [&]()
    {
        const ConnectionState state = static_cast<ConnectionState>(selected_connection_state);
        std::string conf_key = "";

        switch (state)
        {
        case ConnectionState::None:
            return;
        case ConnectionState::Handshake:
            conf_key = Conf::handshaking_key;
            break;
        case ConnectionState::Status:
            conf_key = Conf::status_key;
            break;
        case ConnectionState::Login:
            conf_key = Conf::login_key;
            break;
        case ConnectionState::Play:
            conf_key = Conf::play_key;
            break;
#if PROTOCOL_VERSION > 763 /* > 1.20.1 */
        case ConnectionState::Configuration:
            conf_key = Conf::configuration_key;
            break;
#endif
        }
        std::sort(displayed.begin(), displayed.end(), [](const NameID& a, const NameID& b) { return a.name < b.name; });
        std::sort(hidden.begin(), hidden.end(), [](const NameID& a, const NameID& b) { return a.name < b.name; });

        {
            std::scoped_lock<std::shared_mutex> lock(Conf::conf_mutex);
            ProtocolCraft::Json::Value conf = Conf::LoadConf();
            std::vector<std::string_view> ignored_names(hidden.size());
            for (size_t i = 0; i < hidden.size(); ++i)
            {
                ignored_names[i] = hidden[i].name;
            }
            conf[conf_key][selected_direction == 0 ? Conf::ignored_clientbound_key : Conf::ignored_serverbound_key] = ignored_names;
            Conf::SaveConf(conf);
        }
        {
            // Triger a load config for all associated loggers
            std::scoped_lock<std::mutex> lock(loggers_mutex);
            for (auto& l : loggers)
            {
                l->LoadConfig();
            }
        }
    };

    // Init the values with actual conf values
    {
        std::shared_lock<std::shared_mutex> lock(Conf::conf_mutex);
        const ProtocolCraft::Json::Value conf = Conf::LoadConf();
        is_online = conf.contains(Conf::online_key) && conf[Conf::online_key].is_bool() && conf[Conf::online_key].get<bool>();
        cache_key = (conf.contains(Conf::account_cache_key_key) && conf[Conf::account_cache_key_key].is_string()) ? conf[Conf::account_cache_key_key].get_string() : "";
        log_to_console = conf.contains(Conf::console_log_key) && conf[Conf::console_log_key].is_bool() && conf[Conf::console_log_key].get<bool>();
        network_recap_to_console = conf.contains(Conf::network_recap_to_console_key) && conf[Conf::network_recap_to_console_key].is_bool() && conf[Conf::network_recap_to_console_key].get<bool>();
        log_to_text_file = conf.contains(Conf::text_file_log_key) && conf[Conf::text_file_log_key].is_bool() && conf[Conf::text_file_log_key].get<bool>();
        log_to_bin_file = conf.contains(Conf::binary_file_log_key) && conf[Conf::binary_file_log_key].is_bool() && conf[Conf::binary_file_log_key].get<bool>();
        log_raw_bytes = conf.contains(Conf::raw_bytes_log_key) && conf[Conf::raw_bytes_log_key].is_bool() && conf[Conf::raw_bytes_log_key].get<bool>();
        log_to_replay_file = conf.contains(Conf::replay_log_key) && conf[Conf::replay_log_key].is_bool() && conf[Conf::replay_log_key].get<bool>();
    }
    on_display_changed();


    while (glfwWindowShouldClose(window) == 0)
    {
        // clear the window
        glClear(GL_COLOR_BUFFER_BIT);

        // Init imgui frame
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        {
            ImGui::SetNextWindowPos(ImVec2(0, 0));
            ImGui::SetNextWindowSize(ImVec2(static_cast<float>(width), static_cast<float>(height)));

            ImGui::Begin("SniffCraft Main Window", NULL,
                ImGuiWindowFlags_NoResize |
                ImGuiWindowFlags_NoMove |
                ImGuiWindowFlags_NoCollapse |
                ImGuiWindowFlags_NoSavedSettings |
                ImGuiWindowFlags_NoTitleBar |
                ImGuiWindowFlags_NoScrollbar |
                ImGuiWindowFlags_NoScrollWithMouse
            );
            ImGui::SeparatorText("Application parameters");
            {
                ImGui::TextUnformatted("Server address");
                ImGui::SameLine();
                HelpMarker("Server address, as you would enter it in a minecraft client");
                ImGui::SameLine();
                ImGui::SetNextItemWidth(500.0f);
                ImGui::InputText("##server_address", &server_address);
                if (ImGui::IsItemDeactivatedAfterEdit())
                {
                    std::scoped_lock<std::shared_mutex> lock(Conf::conf_mutex);
                    ProtocolCraft::Json::Value conf = Conf::LoadConf();
                    conf[Conf::server_address_key] = server_address;
                    Conf::SaveConf(conf);
                    ResolveIpPortFromAddress();
                }

                ImGui::BeginDisabled(started);
                ImGui::SameLine(0.0f, 10.0f);
                ImGui::TextUnformatted("Local port");
                ImGui::SameLine();
                HelpMarker("Local port clients will use to connect to this Sniffcraft instance, should be between 1024 and 65535");
                ImGui::SameLine();
                ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x);
                ImGui::InputText("##local_port", &local_port_str, ImGuiInputTextFlags_::ImGuiInputTextFlags_CharsDecimal);
                if (ImGui::IsItemDeactivatedAfterEdit())
                {
                    try
                    {
                        client_port = static_cast<unsigned short>(std::stoul(local_port_str));
                    }
                    catch (std::exception&)
                    {
                        local_port_str = std::to_string(client_port);
                    }
                    std::scoped_lock<std::shared_mutex> lock(Conf::conf_mutex);
                    ProtocolCraft::Json::Value conf = Conf::LoadConf();
                    conf[Conf::local_port_key] = client_port;
                    Conf::SaveConf(conf);
                }
                ImGui::EndDisabled();

                if (ImGui::Checkbox("Authenticated", &is_online))
                {
                    std::scoped_lock<std::shared_mutex> lock(Conf::conf_mutex);
                    ProtocolCraft::Json::Value conf = Conf::LoadConf();
                    conf[Conf::online_key] = is_online;
                    Conf::SaveConf(conf);
                }
                ImGui::SameLine();
                HelpMarker("If checked, you will have to connect with a valid Minecraft account");
                if (is_online)
                {
                    ImGui::SameLine(0.0f, 10.0f);
                    ImGui::TextUnformatted("Credentials cache key");
                    ImGui::SameLine();
                    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x);
                    ImGui::InputTextWithHint("##cache_key", "Key used to select an account in the credentials cache file", &cache_key);
                    if (ImGui::IsItemDeactivatedAfterEdit())
                    {
                        std::scoped_lock<std::shared_mutex> lock(Conf::conf_mutex);
                        ProtocolCraft::Json::Value conf = Conf::LoadConf();
                        conf[Conf::account_cache_key_key] = cache_key;
                        Conf::SaveConf(conf);
                    }
                }

                if (ImGui::Checkbox("Console", &log_to_console))
                {
                    std::scoped_lock<std::shared_mutex> lock(Conf::conf_mutex);
                    ProtocolCraft::Json::Value conf = Conf::LoadConf();
                    conf[Conf::console_log_key] = log_to_console;
                    Conf::SaveConf(conf);
                }
                ImGui::SameLine();
                HelpMarker("If checked, logs will be printed in the console");
                ImGui::SameLine(0.0f, 10.0f);
                if (ImGui::Checkbox("Network recap", &network_recap_to_console))
                {
                    std::scoped_lock<std::shared_mutex> lock(Conf::conf_mutex);
                    ProtocolCraft::Json::Value conf = Conf::LoadConf();
                    conf[Conf::network_recap_to_console_key] = network_recap_to_console;
                    Conf::SaveConf(conf);
                }
                ImGui::SameLine();
                HelpMarker("If checked, a network usage recap will be printed in the console every ~10 seconds");
                ImGui::SameLine(0.0f, 10.0f);
                if (ImGui::Checkbox("Raw bytes", &log_raw_bytes))
                {
                    std::scoped_lock<std::shared_mutex> lock(Conf::conf_mutex);
                    ProtocolCraft::Json::Value conf = Conf::LoadConf();
                    conf[Conf::raw_bytes_log_key] = log_raw_bytes;
                    Conf::SaveConf(conf);
                }
                ImGui::SameLine();
                HelpMarker("If checked, raw bytes will also be part of the logs");
                ImGui::SameLine(0.0f, 10.0f);
                if (ImGui::Checkbox("Text file", &log_to_text_file))
                {
                    std::scoped_lock<std::shared_mutex> lock(Conf::conf_mutex);
                    ProtocolCraft::Json::Value conf = Conf::LoadConf();
                    conf[Conf::text_file_log_key] = log_to_text_file;
                    Conf::SaveConf(conf);
                }
                ImGui::SameLine();
                HelpMarker("If checked, logs will be sent to a text file");
                ImGui::SameLine(0.0f, 10.0f);
                if (ImGui::Checkbox("Binary file", &log_to_bin_file))
                {
                    std::scoped_lock<std::shared_mutex> lock(Conf::conf_mutex);
                    ProtocolCraft::Json::Value conf = Conf::LoadConf();
                    conf[Conf::binary_file_log_key] = log_to_bin_file;
                    Conf::SaveConf(conf);
                }
                ImGui::SameLine();
                HelpMarker("If checked, packets will be saved in a binary file that can be reimported into Sniffcraft GUI");
                ImGui::SameLine(0.0f, 10.0f);
                if (ImGui::Checkbox("Replay file", &log_to_replay_file))
                {
                    std::scoped_lock<std::shared_mutex> lock(Conf::conf_mutex);
                    ProtocolCraft::Json::Value conf = Conf::LoadConf();
                    conf[Conf::replay_log_key] = log_to_replay_file;
                    Conf::SaveConf(conf);
                }
                ImGui::SameLine();
                HelpMarker("If checked, the session will be saved as a replay file compatible with replay mod. /!\\ Current player will NOT be visible in it, as replay mod artificially adds some packets to display it.");

                if (!started)
                {
                    ImGui::PushStyleColor(ImGuiCol_::ImGuiCol_Button, ImVec4(1.0f, 0.0f, 0.0f, 1.0f));
                    if (ImGui::Button("Start"))
                    {
                        started = true;
                        iocontext_thread = std::thread(&Server::run_iocontext, this);
                    }
                    ImGui::PopStyleColor();
                }
                else
                {
                    ImGui::Text("Any connection on 127.0.0.1:%i will be redirected to %s:%i", client_port, server_ip, server_port);
                }
            }


            ImGui::SeparatorText("Display filter");
            {
                if (ImGui::BeginCombo("##connection_state", connection_state_str[selected_connection_state].c_str(), ImGuiComboFlags_WidthFitPreview))
                {
                    for (size_t n = 0; n < connection_state_str.size(); ++n)
                    {
                        const bool is_selected = selected_connection_state == n;
                        if (ImGui::Selectable(connection_state_str[n].c_str(), is_selected))
                        {
                            selected_connection_state = static_cast<int>(n);
                            if (!is_selected)
                            {
                                on_display_changed();
                            }
                        }
                        if (is_selected)
                        {
                            ImGui::SetItemDefaultFocus();
                        }
                    }
                    ImGui::EndCombo();
                }
                ImGui::SameLine();
                if (ImGui::BeginCombo("##network_direction", direction_str[selected_direction].c_str(), ImGuiComboFlags_WidthFitPreview))
                {
                    for (size_t n = 0; n < direction_str.size(); ++n)
                    {
                        const bool is_selected = selected_direction == n;
                        if (ImGui::Selectable(direction_str[n].c_str(), is_selected))
                        {
                            selected_direction = static_cast<int>(n);
                            if (!is_selected)
                            {
                                on_display_changed();
                            }
                        }
                        if (is_selected)
                        {
                            ImGui::SetItemDefaultFocus();
                        }
                    }
                    ImGui::EndCombo();
                }

                const float half_size = 0.5f * (ImGui::GetContentRegionAvail().x - ImGui::GetStyle().ItemSpacing.x);
                ImGui::TextUnformatted("Displayed packets (double click to ignore)");
                const float displayed_size = ImGui::GetItemRectSize().x;
                ImGui::SameLine();
                ImGui::Dummy(ImVec2(half_size - displayed_size - ImGui::GetStyle().ItemSpacing.x, ImGui::GetTextLineHeightWithSpacing()));
                ImGui::SameLine();
                ImGui::TextUnformatted("Hidden packets");
                if (ImGui::BeginListBox("##displayed_packets", ImVec2(half_size, 7 * ImGui::GetTextLineHeightWithSpacing())))
                {
                    for (size_t i = 0; i < displayed.size(); ++i)
                    {
                        ImGui::Selectable(displayed[i].name.data(), false, ImGuiSelectableFlags_AllowDoubleClick);
                        if (ImGui::IsItemHovered())
                        {
                            if (ImGui::BeginTooltip())
                            {
                                ImGui::Text("ID: %i", displayed[i].id);
                                ImGui::EndTooltip();
                            }
                            if (ImGui::IsMouseDoubleClicked(0))
                            {
                                hidden.push_back(displayed[i]);
                                displayed.erase(displayed.begin() + i);
                                --i;
                                on_ignored_changed();
                            }
                        }
                    }
                    ImGui::EndListBox();
                }
                ImGui::SameLine();
                if (ImGui::BeginListBox("##hidden_packets", ImVec2(half_size, 7 * ImGui::GetTextLineHeightWithSpacing())))
                {
                    for (size_t i = 0; i < hidden.size(); ++i)
                    {
                        ImGui::Selectable(hidden[i].name.data(), false, ImGuiSelectableFlags_AllowDoubleClick);
                        if (ImGui::IsItemHovered())
                        {
                            if (ImGui::BeginTooltip())
                            {
                                ImGui::Text("ID: %i", hidden[i].id);
                                ImGui::EndTooltip();
                            }
                            if (ImGui::IsMouseDoubleClicked(0))
                            {
                                displayed.push_back(hidden[i]);
                                hidden.erase(hidden.begin() + i);
                                --i;
                                on_ignored_changed();
                            }
                        }
                    }
                    ImGui::EndListBox();
                }
            }

            ImGui::SeparatorText("Sessions");
            std::tuple<std::shared_ptr<Message>, ConnectionState, Endpoint> additional_ignored_packet = { nullptr, ConnectionState::None, Endpoint::Client };
            {
                std::scoped_lock<std::mutex> lock(loggers_mutex);
                if (loggers.size() > 0 && ImGui::BeginTabBar("loggers", ImGuiTabBarFlags_AutoSelectNewTabs | ImGuiTabBarFlags_FittingPolicyScroll))
                {
                    for (auto it = loggers.begin(); it != loggers.end(); )
                    {
                        bool open = true;
                        if (ImGui::BeginTabItem((*it)->GetBaseFilename().c_str(), &open, ImGuiTabItemFlags_None))
                        {
                            // If a packet ignore button has been pressed, save it to update display later
                            auto ignored_pressed = (*it)->Render();
                            if (std::get<0>(ignored_pressed) != nullptr)
                            {
                                additional_ignored_packet = ignored_pressed;
                            }
                            ImGui::EndTabItem();
                        }
                        if (!open)
                        {
                            loggers.erase(it);
                        }
                        else
                        {
                            ++it;
                        }
                    }
                    ImGui::EndTabBar();
                }
            }

            // Update display afterward because the loggers are locked while rendered
            const auto& [message, connection_state, origin] = additional_ignored_packet;
            if (message != nullptr)
            {
                const int current_selected_connection_state = selected_connection_state;
                const int current_selected_direction = selected_direction;
                // Switch display to the one matching the message
                selected_connection_state = static_cast<int>(connection_state);
                selected_direction = static_cast<int>(origin);
                on_display_changed();
                // Add this message to hidden
                hidden.push_back(NameID{ message->GetName(), message->GetId() });
                for (int i = static_cast<int>(displayed.size()) - 1; i > -1; --i)
                {
                    if (displayed[i].id == message->GetId())
                    {
                        displayed.erase(displayed.begin() + i);
                    }
                }
                on_ignored_changed();
                // Switch back to the previously selected display
                selected_connection_state = current_selected_connection_state;
                selected_direction = current_selected_direction;
                on_display_changed();
            }
            ImGui::End();
        }

        // Render ImGui
        ImGui::Render();
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        // swap buffer
        glfwSwapBuffers(window);

        // process user events
        glfwPollEvents();
    }
}

void HelpMarker(const char* tooltip)
{
    ImGui::TextDisabled("(?)");
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled) && ImGui::BeginTooltip())
    {
        ImGui::PushTextWrapPos(ImGui::GetFontSize() * 35.0f);
        ImGui::TextUnformatted(tooltip);
        ImGui::PopTextWrapPos();
        ImGui::EndTooltip();
    }
}
#endif
