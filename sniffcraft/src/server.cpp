#include "sniffcraft/conf.hpp"
#include "sniffcraft/MinecraftProxy.hpp"
#include "sniffcraft/server.hpp"

#include <botcraft/Network/DNS/DNSMessage.hpp>
#include <botcraft/Network/DNS/DNSSrvData.hpp>

#include <filesystem>
#include <functional>
#include <fstream>
#include <iostream>
#include <utility>

const std::vector<std::string> SplitString(const std::string& s, const char delimiter)
{
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter))
    {
        tokens.push_back(token);
    }
    return tokens;
}

Server::Server(const std::string& conf_path)
{
    this->conf_path = "conf.json";
    if (conf_path.empty())
    {
        std::cerr << "Warning, no conf path specified, using default conf.json instead" << std::endl;
    }
    else
    {
        this->conf_path = conf_path;
    }

    const ProtocolCraft::Json::Value conf = LoadConf();

    client_port = 8686;
    if (!conf.contains(local_port_key) || !conf[local_port_key].is_number())
    {
        std::cerr << "Warning, no valid LocalPort in conf file, using default 8686 instead" << std::endl;
    }
    else
    {
        client_port = conf[local_port_key].get_number<unsigned short>();
    }
    acceptor = std::make_unique<asio::ip::tcp::acceptor>(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), client_port));

    server_address = "127.0.0.1:25565";
    if (!conf.contains(server_address_key) || !conf[server_address_key].is_string())
    {
        std::cerr << "Warning, no valid ServerAddress in conf file, using default 127.0.0.1:25565 instead" << std::endl;
    }
    else
    {
        server_address = conf[server_address_key].get_string();
    }
    ResolveIpPortFromAddress();

    proxies_cleaning_thread = std::thread(&Server::CleanProxies, this);
}

Server::~Server()
{
    if (running)
    {
        running = false;
        proxies_cleaning_thread.join();
    }
}

void Server::run()
{
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
        new_proxy->Start(server_ip, server_port, conf_path);
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

    const std::vector<std::string> splitted_port = SplitString(server_address, ':');
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
    question.SetNameLabels(SplitString("_minecraft._tcp." + server_address, '.'));
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

ProtocolCraft::Json::Value Server::LoadConf() const
{
    if (!std::filesystem::exists(conf_path))
    {
        Json::Value packet_lists = {
            { ignored_clientbound_key, Json::Array() },
            { ignored_serverbound_key, Json::Array() },
            { detailed_clientbound_key, Json::Array() },
            { detailed_serverbound_key, Json::Array() },
        };
        Json::Value default_conf = {
            { server_address_key, "127.0.0.1:25565" },
            { local_port_key, 8686 },
            { text_file_log_key, true },
            { console_log_key, false },
            { replay_log_key, false },
            { raw_bytes_log_key, false },
            { online_key, false },
            { headless_key, false },
            { network_recap_to_console_key, false },
            { account_cache_key_key, "" },
            { handshaking_key, packet_lists },
            { status_key, packet_lists },
            { login_key, packet_lists },
            { configuration_key, packet_lists },
            { play_key, packet_lists }
        };
        std::ofstream outfile(conf_path, std::ios::out);
        outfile << default_conf.Dump(4);
    }

    std::ifstream file = std::ifstream(conf_path, std::ios::in);
    if (!file.is_open())
    {
        throw std::runtime_error("Error trying to open conf file at: " + conf_path);
    }

    Json::Value json;
    file >> json;
    file.close();

    if (!json.is_object())
    {
        throw std::runtime_error("Error parsing conf file at: " + conf_path);
    }

    return json;
}

void Server::SaveConf(const ProtocolCraft::Json::Value& conf) const
{
    std::ofstream file = std::ofstream(conf_path, std::ios::out);
    if (!file.is_open())
    {
        throw std::runtime_error("Error trying to open conf file at: " + conf_path);
    }

    file << conf.Dump(4);
    file.close();
}

void Server::CleanProxies()
{
    running = true;
    while (running)
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
