#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <asio.hpp>
#include "protocolCraft/Utilities/Json.hpp"

class BaseProxy;

class Server
{
public:
    Server(const std::string& conf_path);
    ~Server();
    void run();

private:
    void listen_connection();
    void handle_accept(BaseProxy* new_proxy, const asio::error_code &ec);
    void ResolveIpPortFromAddress();

    BaseProxy* GetNewMinecraftProxy();

    ProtocolCraft::Json::Value LoadConf() const;
    void SaveConf(const ProtocolCraft::Json::Value& conf) const;

    void CleanProxies();
    
private:
    std::string conf_path;
    std::string server_address;
    std::string server_ip;
    unsigned short server_port;
    unsigned short client_port;

    asio::io_context io_context;
    std::unique_ptr<asio::ip::tcp::acceptor> acceptor;

    std::vector<std::unique_ptr<BaseProxy>> proxies;
    std::mutex proxies_mutex;
    std::thread proxies_cleaning_thread;

    std::atomic<bool> running;
};
