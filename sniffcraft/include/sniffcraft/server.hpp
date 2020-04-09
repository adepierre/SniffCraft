#pragma once

#include <asio.hpp>

class MinecraftProxy;

class Server
{
public:
    Server(asio::io_context& io_context, const short client_port,
        const std::string& server_address, const short server_port,
        const std::string& logconf_path_);

private:
    void start_accept();
    void handle_accept(MinecraftProxy* new_proxy, const asio::error_code &ec);
    
private:
    asio::io_context& io_context_;
    asio::ip::tcp::acceptor acceptor_;

    std::string server_address_;
    short server_port_;

    std::string logconf_path;
};

