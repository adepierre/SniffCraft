#include "sniffcraft/server.hpp"
#include "sniffcraft/MinecraftProxy.hpp"

#include <botcraft/Network/DNS/DNSMessage.hpp>
#include <botcraft/Network/DNS/DNSSrvData.hpp>

#include <botcraft/Network/AESEncrypter.hpp>
#include <botcraft/Network/Authentifier.hpp>

#include <functional>
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

Server::Server(asio::io_context& io_context, const unsigned short client_port,
    const std::string& server_address, const std::string& conf_path_) :
    io_context_(io_context),
    acceptor_(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), client_port)),
    conf_path(conf_path_),
    client_port_(client_port)
{
    ResolveIpPortFromAddress(server_address);
    proxies_cleaning_thread = std::thread(&Server::CleanProxies, this);
    start_accept();
}

void Server::start_accept()
{
    BaseProxy* proxy = GetNewProxy();

    acceptor_.async_accept(proxy->ClientSocket(),
        std::bind(&Server::handle_accept, this, proxy,
            std::placeholders::_1));

    std::cout << "Ready to redirect any client connection on 127.0.0.1:" << client_port_ << " to " << server_ip_ << ":" << server_port_ << std::endl;
}

void Server::handle_accept(BaseProxy* new_proxy, const asio::error_code& ec)
{
    if (!ec)
    {
        new_proxy->Start(server_ip_, server_port_);
    }
    else
    {
        std::cerr << "Failed to start new proxy" << std::endl;
    }
    start_accept();
}

void Server::ResolveIpPortFromAddress(const std::string& address)
{
    std::string addressOnly;

    const std::vector<std::string> splitted_port = SplitString(address, ':');
    // address:port format
    if (splitted_port.size() > 1)
    {
        try
        {
            server_port_ = std::stoi(splitted_port[1]);
            server_ip_ = splitted_port[0];
            return;
        }
        catch (const std::exception&)
        {
            server_port_ = 0;
        }
        addressOnly = splitted_port[0];
    }
    // address only format
    else
    {
        addressOnly = address;
        server_port_ = 0;
    }

    // If port is unknown we first try a SRV DNS lookup
    std::cout << "Performing SRV DNS lookup on " << "_minecraft._tcp." << addressOnly << " to find an endpoint" << std::endl;
    asio::ip::udp::socket udp_socket(io_context_);

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
    question.SetNameLabels(SplitString("_minecraft._tcp." + address, '.'));
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
        server_ip_ = "";
        for (int i = 0; i < data.GetNameLabels().size(); ++i)
        {
            server_ip_ += data.GetNameLabels()[i] + (i == data.GetNameLabels().size() - 1 ? "" : ".");
        }
        server_port_ = data.GetPort();

        std::cout << "SRV DNS lookup successful!" << std::endl;
        return;
    }
    std::cout << "SRV DNS lookup failed to find an address" << std::endl;

    // If we are here either the port was given or the SRV failed 
    // In both cases we need to assume the given address is the correct one
    server_port_ = (server_port_ == 0) ? 25565 : server_port_;
    server_ip_ = addressOnly;
}

BaseProxy* Server::GetNewProxy()
{
    std::lock_guard<std::mutex> lock(proxies_mutex);
    // Create a new proxy
    std::unique_ptr<BaseProxy> proxy = std::make_unique<MinecraftProxy>(io_context_, conf_path);
    proxies.push_back(std::move(proxy));

    return proxies.back().get();
}

void Server::CleanProxies()
{
    while (true)
    {
        {
            std::lock_guard<std::mutex> lock(proxies_mutex);
            // Clean old proxies
            for (int i = proxies.size() - 1; i > -1; --i)
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
