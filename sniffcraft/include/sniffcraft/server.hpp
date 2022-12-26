#pragma once

#include <memory>
#include <vector>
#include <asio.hpp>

#include "sniffcraft/BaseProxy.hpp"

class Server
{
public:
    Server(asio::io_context& io_context, const unsigned short client_port,
        const std::string& server_address, const std::string& conf_path_);

private:
    void start_accept();
    void handle_accept(BaseProxy* new_proxy, const asio::error_code &ec);
    void ResolveIpPortFromAddress(const std::string& address);

    /// @brief Clean old proxies and get a fresh one ready
    /// @return A pointer to a BaseProxy item
    BaseProxy* GetNewProxy();
    
private:
    asio::io_context& io_context_;
    asio::ip::tcp::acceptor acceptor_;

    std::string server_ip_;
    unsigned short server_port_;
    unsigned short client_port_;

    std::string conf_path;

    std::vector<std::unique_ptr<BaseProxy>> proxies;
};

