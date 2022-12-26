#pragma once

#include <list>
#include <vector>
#include <mutex>
#include <memory>
#include <atomic>

#include <asio.hpp>

#include "sniffcraft/Connection.hpp"
#include "sniffcraft/enums.hpp"

/// @brief A base proxy class that will transfer all data
/// both way without changing anything. Can be overriden by 
class BaseProxy
{
public:
    BaseProxy(asio::io_context& io_context);
    virtual ~BaseProxy();

    /// @brief Starts the connection process to a given server
    /// @param server_address IP address of the server
    /// @param server_port port to connect to
    virtual void Start(const std::string& server_address, const unsigned short server_port);

    /// @brief Get the client connection underlying socket
    /// @return A reference to the client socket
    asio::ip::tcp::socket& ClientSocket();

    bool Running();

protected:
    /// @brief Function called when new data are available. On BaseProxy, just
    /// send the data to the other endpoint without any other processing. Override
    /// to do more advanced stuff. It will always be called by one thread at the same
    /// time, and you don't need to worry about any thread locking stuff.
    /// @param data Iterator to the first element of the data
    /// @param length Size of the available data
    /// @param source Where the data are coming from
    /// @return The size of data that have been processed and should
    /// be removed from the incoming buffer
    virtual size_t ProcessData(const std::vector<unsigned char>::const_iterator& data, const size_t length, const Endpoint source);

    /// @brief Close both client and server connections
    void Close();

private:
    /// @brief Use as callback when server connection has new data
    void NotifyServerData(const size_t length);
    /// @brief Use as callback when client connection has new data
    void NotifyClientData(const size_t length);

    /// @brief Function running in data_processing_thread
    void ReadIncomingData();

protected:
    /// @brief In/Out connection to the client
    Connection client_connection;
    /// @brief In/Out connection to the server
    Connection server_connection;

    std::string server_ip_;
    unsigned short server_port_;

private:
    asio::io_context& io_context_;

    /// @brief Running thread to process incoming data from
    /// both client and server
    std::thread data_processing_thread;

    /// @brief Everytime one connection has data,
    /// it adds the source Endpoint in this queue
    /// and the number of bytes transferred this time
    std::list<std::pair<Endpoint, size_t> > data_sources;
    /// @brief Mutex to protect the data_sources
    std::mutex data_sources_mutex;
    /// @brief Condition variable notified everytime
    /// there is a new entry in data_sources
    std::condition_variable data_source_cv;

    /// @brief History of data received by the client connection
    std::vector<unsigned char> client_received_data;
    /// @brief History of data received by the server connection
    std::vector<unsigned char> server_received_data;

    std::atomic<bool> process_data_ready;
    std::atomic<bool> closed;
};
