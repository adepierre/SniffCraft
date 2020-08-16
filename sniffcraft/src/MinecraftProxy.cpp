#include "sniffcraft/MinecraftProxy.hpp"
#include "sniffcraft/Compression.hpp"

#include <protocolCraft/BinaryReadWrite.hpp>
#include <protocolCraft/MessageFactory.hpp>

#include <functional>
#include <iostream>
#include <memory>

MinecraftProxy::MinecraftProxy(asio::io_context& io_context, const std::string &logconf_path) :
    client_socket_(io_context),
    server_socket_(io_context),
    logger(logconf_path)
{
    connection_state = ProtocolCraft::ConnectionState::Handshake;
    client_closed = false;
    server_closed = false;

    compression_threshold = -1;
}

asio::ip::tcp::socket& MinecraftProxy::ClientSocket()
{
    return client_socket_;
}

asio::ip::tcp::socket& MinecraftProxy::ServerSocket()
{
    return server_socket_;
}

void MinecraftProxy::Start(const std::string& server_address, const short server_port)
{
    std::cout << "Starting new proxy to " << server_address << ":" << server_port << std::endl;

    // Try to connect to remote server
    server_socket_.async_connect(
        asio::ip::tcp::endpoint(asio::ip::address::from_string(server_address), server_port),
        std::bind(&MinecraftProxy::handle_server_connect, this, std::placeholders::_1));
}

void MinecraftProxy::handle_server_connect(const asio::error_code& ec)
{
    if (!ec)
    {
        // Read from server
        server_socket_.async_read_some(asio::buffer(input_server_buffer_.data(), MAX_LENGTH),
            std::bind(&MinecraftProxy::handle_server_read, this,
                std::placeholders::_1, std::placeholders::_2));

        // Read from client
        client_socket_.async_read_some(asio::buffer(input_client_buffer_.data(), MAX_LENGTH),
            std::bind(&MinecraftProxy::handle_client_read, this,
                std::placeholders::_1, std::placeholders::_2));
    }
    else
    {
        Close();
    }
}

void MinecraftProxy::handle_server_read(const asio::error_code& ec, const size_t& bytes_transferred)
{
    if (!ec)
    {
        ExtractPacketFromIncomingData(Origin::Server, bytes_transferred);

        server_socket_.async_read_some(asio::buffer(input_server_buffer_.data(), MAX_LENGTH),
            std::bind(&MinecraftProxy::handle_server_read, this,
                std::placeholders::_1, std::placeholders::_2));
    }
    else
    {
        Close();
    }
}

void MinecraftProxy::handle_client_write(const asio::error_code& ec)
{
    if (!ec)
    {
        output_client_mutex_.lock();
        output_client_data_.pop_front();

        if (!output_client_data_.empty())
        {
            output_client_buffer_ = output_client_data_.front();
            asio::async_write(client_socket_, asio::buffer(output_client_buffer_.data(), output_client_buffer_.size()),
                std::bind(&MinecraftProxy::handle_client_write, this,
                    std::placeholders::_1));
        }
        output_client_mutex_.unlock();
    }
    else
    {
        Close();
    }
}

void MinecraftProxy::handle_client_read(const asio::error_code& ec, const size_t& bytes_transferred)
{
    if (!ec)
    {
        ExtractPacketFromIncomingData(Origin::Client, bytes_transferred);

        client_socket_.async_read_some(asio::buffer(input_client_buffer_.data(), MAX_LENGTH),
            std::bind(&MinecraftProxy::handle_client_read, this,
                std::placeholders::_1, std::placeholders::_2));
    }
    else
    {
        Close();
    }
}

void MinecraftProxy::handle_server_write(const asio::error_code& ec)
{
    if (!ec)
    {
        output_server_mutex_.lock();
        output_server_data_.pop_front();

        if (!output_server_data_.empty())
        {
            output_server_buffer_ = output_server_data_.front();
            asio::async_write(server_socket_, asio::buffer(output_server_buffer_.data(), output_server_buffer_.size()),
                std::bind(&MinecraftProxy::handle_server_write, this,
                    std::placeholders::_1));
        }
        output_server_mutex_.unlock();
    }
    else
    {
        Close();
    }
}

void MinecraftProxy::Close()
{
    if (client_closed && server_closed)
    {
        return;
    }

    if (client_socket_.is_open())
    {
        client_socket_.close();
        client_closed = true;
    }

    if (server_socket_.is_open())
    {
        server_socket_.close();
        server_closed = true;
    }

    std::cout << "Session closed" << std::endl;
    
    delete this;
}

void MinecraftProxy::ExtractPacketFromIncomingData(const Origin from, const size_t& bytes_transferred)
{
    const std::array<unsigned char, MAX_LENGTH>& src_buffer = (from == Origin::Server) ? input_server_buffer_ : input_client_buffer_;
    std::vector<unsigned char>& src_data = (from == Origin::Server) ? input_server_data : input_client_data_;
    std::deque<std::vector<unsigned char> >& output_dst_data = (from == Origin::Server) ? output_client_data_ : output_server_data_;
    std::mutex& output_data_mutex = (from == Origin::Server) ? output_client_mutex_ : output_server_mutex_;
    std::vector<unsigned char>& output_buffer_ = (from == Origin::Server) ? output_client_buffer_ : output_server_buffer_;

    src_data.insert(std::end(src_data), std::begin(src_buffer), std::begin(src_buffer) + bytes_transferred);

    while (src_data.size() != 0)
    {
        std::vector<unsigned char>::const_iterator read_iter = src_data.begin();
        size_t max_length = src_data.size();
        int packet_length = 0;

        // We need a try catch in case all the bytes of 
        // the varint are not in this buffer
        try
        {
            packet_length = ProtocolCraft::ReadVarInt(read_iter, max_length);
        }
        catch (const std::exception&)
        {
            break;
        }

        int bytes_read = std::distance<std::vector<unsigned char>::const_iterator>(std::begin(src_data), read_iter);
        
        if (packet_length > 0 && src_data.size() >= bytes_read + packet_length)
        {
            size_t parse_max_size = packet_length;

            ParsePacket(from, read_iter, parse_max_size);

            std::vector<unsigned char> output_packet(std::begin(src_data), std::begin(src_data) + bytes_read + packet_length);

            output_data_mutex.lock();
            const bool write_in_progress = !output_dst_data.empty();
            output_dst_data.push_back(output_packet);

            if (!write_in_progress)
            {
                output_buffer_ = output_dst_data.front();
                if ((from == Origin::Server))
                {
                    asio::async_write(client_socket_, asio::buffer(output_buffer_.data(), output_buffer_.size()),
                        std::bind(&MinecraftProxy::handle_client_write, this,
                            std::placeholders::_1));
                }
                else
                {
                    asio::async_write(server_socket_, asio::buffer(output_buffer_.data(), output_buffer_.size()),
                        std::bind(&MinecraftProxy::handle_server_write, this,
                            std::placeholders::_1));
                }
            }
            output_data_mutex.unlock();

            src_data.erase(std::begin(src_data), std::begin(src_data) + bytes_read + packet_length);
        }
        else
        {
            break;
        }
    }
}

void MinecraftProxy::ParsePacket(const Origin from, std::vector<unsigned char>::const_iterator& read_iter, size_t& max_length)
{
    int minecraftID = -1;
    std::vector<unsigned char> uncompressed;

    if (compression_threshold >= 0)
    {
        int data_length = ProtocolCraft::ReadVarInt(read_iter, max_length);

        if (data_length != 0)
        {
            uncompressed = Decompress(std::vector<unsigned char>(read_iter, read_iter + max_length), 0);
            read_iter = std::begin(uncompressed);
            max_length = uncompressed.size();
        }
    }

    minecraftID = ProtocolCraft::ReadVarInt(read_iter, max_length);

    std::shared_ptr<ProtocolCraft::Message> msg;

    if (from == Origin::Client)
    {
        msg = ProtocolCraft::MessageFactory::CreateMessageServerbound(minecraftID, connection_state);
    }
    else if (from == Origin::Server)
    {
        msg = ProtocolCraft::MessageFactory::CreateMessageClientbound(minecraftID, connection_state);
    }

    if (msg != nullptr)
    {
        try
        {
            msg->Read(read_iter, max_length);
            msg->Dispatch(this);
        }
        catch (const std::exception & ex)
        {
            std::cout << ((from == Origin::Server) ? "Server --> Client: " : "Client --> Server: ") <<
                "PARSING EXCEPTION: " << ex.what() << " || " << msg->GetName() << std::endl;
        }
    }
    else
    {
        std::cout << ((from == Origin::Server) ? "Server --> Client: " : "Client --> Server: ") <<
            "NULL MESSAGE WITH ID: " << minecraftID << std::endl;
    }

    logger.Log(msg, connection_state, from);
}

void MinecraftProxy::Handle(ProtocolCraft::Message& msg)
{

}

void MinecraftProxy::Handle(ProtocolCraft::Handshake& msg)
{
    connection_state = (ProtocolCraft::ConnectionState)msg.GetNextState();
}

void MinecraftProxy::Handle(ProtocolCraft::LoginSuccess& msg)
{
    connection_state = ProtocolCraft::ConnectionState::Play;
}

void MinecraftProxy::Handle(ProtocolCraft::SetCompression& msg)
{
    compression_threshold = msg.GetThreshold();
}
