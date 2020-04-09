#include "sniffcraft/server.hpp"
#include "sniffcraft/MinecraftProxy.hpp"

#include <functional>
#include <iostream>
#include <utility>

Server::Server(asio::io_context& io_context, const short client_port,
    const std::string& server_address, const short server_port, const std::string &logconf_path_) : 
    io_context_(io_context),
    acceptor_(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), client_port)),
    server_address_(server_address),
    server_port_(server_port),
    logconf_path(logconf_path_)
{
    start_accept();
}

void Server::start_accept()
{
    MinecraftProxy* new_proxy = new MinecraftProxy(io_context_, logconf_path);
    acceptor_.async_accept(new_proxy->ClientSocket(),
        std::bind(&Server::handle_accept, this, new_proxy,
            std::placeholders::_1));
}

void Server::handle_accept(MinecraftProxy* new_proxy, const asio::error_code& ec)
{
    if (!ec)
    {
        new_proxy->Start(server_address_, server_port_);
    }
    else
    {
        delete new_proxy;
    }
    start_accept();
}
