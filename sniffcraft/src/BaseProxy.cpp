#include "sniffcraft/BaseProxy.hpp"

#include <iostream>

BaseProxy::BaseProxy(asio::io_context& io_context) :
    io_context_(io_context),
    client_connection(io_context),
    server_connection(io_context)
{
    closed = true;
}

BaseProxy::~BaseProxy()
{
    Close();
    data_source_cv.notify_one();
    if (data_processing_thread.joinable())
    {
        data_processing_thread.join();
    }
}

void BaseProxy::Start(const std::string& server_address, const unsigned short server_port)
{
    std::cout << "Starting new proxy to " << server_address << ":" << server_port << std::endl;
    server_ip_ = server_address;
    server_port_ = server_port;

    // Try to connect to remote server
    asio::ip::tcp::resolver resolver(io_context_);
    asio::ip::tcp::resolver::query query(server_ip_, std::to_string(server_port_));
    asio::ip::tcp::resolver::iterator iterator = resolver.resolve(query);
    
    asio::error_code ec;
    asio::connect(server_connection.GetSocket(), iterator, ec);

    if (ec)
    {
        Close();
        std::cerr << "Error trying to establish connection to "
            << server_address << ":" << server_port
            << ": " << ec
            << std::endl;
        return;
    }

    closed = false;

    // Once connected, we can start the processing thread
    process_data_ready = false;
    data_processing_thread = std::thread(&BaseProxy::ReadIncomingData, this);

    // Wait for the thread to be launched and ready to process incoming data
    while (!process_data_ready)
    {

    }

    client_connection.SetCallback(
        std::bind(
            &BaseProxy::NotifyClientData, this,
            std::placeholders::_1
        )
    );

    server_connection.SetCallback(
        std::bind(
            &BaseProxy::NotifyServerData, this,
            std::placeholders::_1
        )
    );

    client_connection.StartListeningAndWriting();
    server_connection.StartListeningAndWriting();
}

void BaseProxy::Close()
{
    client_connection.Close();
    server_connection.Close();
    closed = true;
}

bool BaseProxy::Running()
{
    if (!closed && (client_connection.Closed() || server_connection.Closed()))
    {
        Close();
    }
    return !closed;
}

asio::ip::tcp::socket& BaseProxy::ClientSocket()
{
    return client_connection.GetSocket();
}

size_t BaseProxy::ProcessData(const std::vector<unsigned char>::const_iterator& data, const size_t length, const Endpoint source)
{
    Connection& dst_connection = source == Endpoint::Server ? client_connection : server_connection;

    // Transfer the data to the other endpoint
    dst_connection.WriteData(&(*data), length);
    return length;
}

void BaseProxy::NotifyServerData(const size_t length)
{
    {
        std::lock_guard<std::mutex> data_sources_lock(data_sources_mutex);
        data_sources.push_back({ Endpoint::Server, length });
    }
    data_source_cv.notify_one();
}

void BaseProxy::NotifyClientData(const size_t length)
{
    {
        std::lock_guard<std::mutex> data_sources_lock(data_sources_mutex);
        data_sources.push_back({ Endpoint::Client, length });
    }
    data_source_cv.notify_one();
}

void BaseProxy::ReadIncomingData()
{
    // Run indefinitely
    while (!closed)
    {
        if (server_connection.Closed() && client_connection.Closed())
        {
            Close();
            break;
        }

        // Wait for some data
        {
            std::unique_lock<std::mutex> data_source_lock(data_sources_mutex);
            process_data_ready = true;
            data_source_cv.wait(data_source_lock);
        }

        if (closed)
        {
            break;
        }

        while (!data_sources.empty())
        {
            Endpoint data_source = Endpoint::Server;
            // Retrieve the origin of the data, but don't remove it in case we need
            // to wait for more data to get a full packet
            {
                std::lock_guard<std::mutex> data_source_lock(data_sources_mutex);
                data_source = data_sources.front().first;
            }

            // Process the data coming from this endpoint
            Connection& src_connection = data_source == Endpoint::Server ? server_connection : client_connection;
            std::vector<unsigned char>& received_data = data_source == Endpoint::Server ? server_received_data : client_received_data;
            // Read all new data from this connection
            src_connection.RetreiveData(received_data);

            // Do something with the data
            size_t data_to_remove = ProcessData(received_data.cbegin(), received_data.size(), data_source);

            if (data_to_remove == 0)
            {
                continue;
            }

            if (data_to_remove > received_data.size())
            {
                std::cerr << "Warning, asked to remove more data than possible" << std::endl;
                data_to_remove = received_data.size();
            }

            // Remove the data from the buffer
            received_data.erase(received_data.begin(), received_data.begin() + data_to_remove);

            // Remove all data_sources elements that refers to data we already removed
            {
                std::lock_guard<std::mutex> data_source_lock(data_sources_mutex);
                std::list<std::pair<Endpoint, size_t>>::iterator it = data_sources.begin();
                size_t already_removed = 0;
                while (it != data_sources.end())
                {
                    // If this is from the endpoint we processed
                    if (it->first == data_source)
                    {
                        // If we cleared all the data from this update, remove this entry
                        // as it's fully processed, and increment the iterator to next item
                        if (already_removed + it->second <= data_to_remove)
                        {
                            already_removed += it->second;
                            data_sources.erase(it++);
                        }
                        // We only used part of the data from this update, so set it's new size
                        else
                        {
                            it->second = it->second - (data_to_remove - already_removed);
                            already_removed = data_to_remove;
                        }

                        // If we removed the right amount of elements, we can stop iterating the list
                        if (already_removed == data_to_remove)
                        {
                            break;
                        }
                    }
                    else
                    {
                        ++it;
                    }
                }
            }

            if (server_connection.Closed())
            {
                client_connection.Close();
            }
            if (client_connection.Closed())
            {
                server_connection.Close();
            }
        }
    }
}
