#pragma once

#include <asio.hpp>
#include <deque>
#include <vector>
#include <mutex>

#include <protocolCraft/Handler.hpp>

#include "sniffcraft/enums.hpp"
#include "sniffcraft/Logger.hpp"
#include "sniffcraft/ReplayModLogger.hpp"

#define MAX_LENGTH 1024

class MinecraftProxy : public ProtocolCraft::Handler
{
public:
    MinecraftProxy(asio::io_context& io_context, const std::string &logconf_path);
    void Start(const std::string& server_address, const unsigned short server_port);
    void Close();
    asio::ip::tcp::socket& ClientSocket();
    asio::ip::tcp::socket& ServerSocket();

private:
    void handle_server_connect(const asio::error_code &ec);

    void handle_server_read(const asio::error_code& ec, const size_t& bytes_transferred);
    void handle_client_write(const asio::error_code& ec);

    void handle_client_read(const asio::error_code& ec, const size_t& bytes_transferred);
    void handle_server_write(const asio::error_code& ec);

    void ExtractPacketFromIncomingData(const Origin from, const size_t& bytes_transferred);
    void ParsePacket(const Origin from, std::vector<unsigned char>::const_iterator& read_iter, size_t& max_length);

    const std::vector<unsigned char> PacketToBytes(const ProtocolCraft::Message& msg);

private:
    virtual void Handle(ProtocolCraft::Message& msg) override;
    virtual void Handle(ProtocolCraft::ServerboundClientIntentionPacket& msg) override;
    virtual void Handle(ProtocolCraft::ClientboundGameProfilePacket& msg) override;
    virtual void Handle(ProtocolCraft::ClientboundLoginCompressionPacket& msg) override;
    virtual void Handle(ProtocolCraft::ClientboundHelloPacket& msg) override;

private:
    asio::io_context& io_context_;

    asio::ip::tcp::socket client_socket_;
    std::array<unsigned char, MAX_LENGTH> input_client_buffer_;
    asio::ip::tcp::socket server_socket_;
    std::array<unsigned char, MAX_LENGTH> input_server_buffer_;
    bool client_closed;
    bool server_closed;

    std::deque<std::vector<unsigned char> > output_client_data_;
    std::mutex output_client_mutex_;
    std::vector<unsigned char> output_client_buffer_;
    std::deque<std::vector<unsigned char> > output_server_data_;
    std::mutex output_server_mutex_;
    std::vector<unsigned char> output_server_buffer_;

    std::vector<unsigned char> input_client_data_;
    std::vector<unsigned char> input_server_data;

    ProtocolCraft::ConnectionState connection_state;

    std::vector<unsigned char> client_replacement_data;
    std::vector<unsigned char> server_replacement_data;

    int compression_threshold;

    Logger logger;
    ReplayModLogger replay_logger;
    std::string server_ip_;
    unsigned short server_port_;
};

