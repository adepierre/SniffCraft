#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <asio.hpp>

#include "protocolCraft/Utilities/Json.hpp"

class BaseProxy;
#ifdef WITH_GUI
struct GLFWwindow;
class Logger;
#endif

class Server
{
public:
    Server();
    ~Server();
    void run();

private:
    void run_iocontext();
    void listen_connection();
    void handle_accept(BaseProxy* new_proxy, const asio::error_code &ec);
    void ResolveIpPortFromAddress();

    BaseProxy* GetNewMinecraftProxy();
    void CleanProxies();

#ifdef WITH_GUI
    void Render();
    void InternalRenderLoop(GLFWwindow* window);
#endif

private:
    std::string server_address;
    std::string server_ip;
    unsigned short server_port;
    unsigned short client_port;

    asio::io_context io_context;
    std::unique_ptr<asio::ip::tcp::acceptor> acceptor;

    std::vector<std::unique_ptr<BaseProxy>> proxies;
    std::mutex proxies_mutex;
    std::thread proxies_cleaning_thread;
    std::atomic<bool> proxies_cleaning_thread_running;

#ifdef WITH_GUI
    std::thread iocontext_thread;
    std::mutex loggers_mutex;
    std::vector<std::shared_ptr<Logger>> loggers;
#endif
};
