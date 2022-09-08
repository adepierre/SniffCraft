#include "sniffcraft/MinecraftProxy.hpp"
#include "sniffcraft/Compression.hpp"

#include <protocolCraft/BinaryReadWrite.hpp>
#include <protocolCraft/MessageFactory.hpp>

#include <botcraft/Network/AESEncrypter.hpp>
#include <botcraft/Network/Authentifier.hpp>
#if PROTOCOL_VERSION > 758
#include <botcraft/Utilities/StringUtilities.hpp>
#endif

#include <nlohmann/json.hpp>

#include <functional>
#include <iostream>
#include <memory>

MinecraftProxy::MinecraftProxy(asio::io_context& io_context, const std::string& conf_path) :
    io_context_(io_context),
    client_socket_(io_context),
    server_socket_(io_context),
    logger(conf_path),
    replay_logger(conf_path)
{
    connection_state = ProtocolCraft::ConnectionState::Handshake;
    client_closed = false;
    server_closed = false;

    compression_threshold = -1;

    LoadConfig(conf_path);
}

asio::ip::tcp::socket& MinecraftProxy::ClientSocket()
{
    return client_socket_;
}

asio::ip::tcp::socket& MinecraftProxy::ServerSocket()
{
    return server_socket_;
}

void MinecraftProxy::Start(const std::string& server_address, const unsigned short server_port)
{
    std::cout << "Starting new proxy to " << server_address << ":" << server_port << std::endl;
    server_ip_ = server_address;
    server_port_ = server_port;

    replay_logger.SetServerName(server_ip_ + ":" + std::to_string(server_port_));

    // Try to connect to remote server
    asio::ip::tcp::resolver resolver(io_context_);
    asio::ip::tcp::resolver::query query(server_ip_, std::to_string(server_port_));
    asio::ip::tcp::resolver::iterator iterator = resolver.resolve(query);

    asio::async_connect(server_socket_, iterator,
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
        ExtractPacketFromIncomingData(Endpoint::Server, bytes_transferred);

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
        ExtractPacketFromIncomingData(Endpoint::Client, bytes_transferred);

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

void MinecraftProxy::ExtractPacketFromIncomingData(const Endpoint from, const size_t& bytes_transferred)
{
    const std::array<unsigned char, MAX_LENGTH>& src_buffer = (from == Endpoint::Server) ? input_server_buffer_ : input_client_buffer_;
    std::vector<unsigned char>& src_data = (from == Endpoint::Server) ? input_server_data : input_client_data_;
    std::vector<unsigned char>& replacement_data = (from == Endpoint::Server) ? server_replacement_data : client_replacement_data;
    Endpoint destination = (from == Endpoint::Server) ? Endpoint::Client : Endpoint::Server;

    // If data are from the server and encryption is enabled,
    // we first need to decrypt the data
#ifdef USE_ENCRYPTION
    if (from == Endpoint::Server && encrypter)
    {
        std::vector<unsigned char> decrypted(std::begin(src_buffer), std::begin(src_buffer) + bytes_transferred);
        decrypted = encrypter->Decrypt(decrypted);
        src_data.insert(std::end(src_data), std::begin(decrypted), std::end(decrypted));
    }
    else
    {
        src_data.insert(std::end(src_data), std::begin(src_buffer), std::begin(src_buffer) + bytes_transferred);
    }
#else
    src_data.insert(std::end(src_data), std::begin(src_buffer), std::begin(src_buffer) + bytes_transferred);
#endif


    while (src_data.size() != 0)
    {
        std::vector<unsigned char>::const_iterator read_iter = src_data.begin();
        size_t max_length = src_data.size();
        int packet_length = 0;

        // We need a try catch in case all the bytes of 
        // the varint are not in this buffer
        try
        {
            packet_length = ProtocolCraft::ReadData<ProtocolCraft::VarInt>(read_iter, max_length);
        }
        catch (const std::exception&)
        {
            break;
        }

        int bytes_read = std::distance<std::vector<unsigned char>::const_iterator>(std::begin(src_data), read_iter);
        
        if (packet_length > 0 && src_data.size() >= bytes_read + packet_length)
        {
            size_t parse_max_size = packet_length;

            replacement_data.clear();
            ParsePacket(from, read_iter, parse_max_size);

            std::vector<unsigned char> output_packet;
            if (replacement_data.size() == 0)
            {
                output_packet = std::vector<unsigned char>(std::begin(src_data), std::begin(src_data) + bytes_read + packet_length);
            }
            // Packet of size 1 don't exist, so we use this as a signal
            // the data should NOT be transmitted to the other endpoint
            else if (replacement_data.size() > 1)
            {
                output_packet = replacement_data;
            }

            SendDataTo(output_packet, destination);

            src_data.erase(std::begin(src_data), std::begin(src_data) + bytes_read + packet_length);
        }
        else
        {
            break;
        }
    }
}

void MinecraftProxy::ParsePacket(const Endpoint from, std::vector<unsigned char>::const_iterator& read_iter, size_t& max_length)
{
    int minecraftID = -1;
    std::vector<unsigned char> uncompressed;

    if (compression_threshold >= 0)
    {
        int data_length = ProtocolCraft::ReadData<ProtocolCraft::VarInt>(read_iter, max_length);

        if (data_length != 0)
        {
            uncompressed = Decompress(std::vector<unsigned char>(read_iter, read_iter + max_length), 0);
            read_iter = std::begin(uncompressed);
            max_length = uncompressed.size();
        }
    }

    minecraftID = ProtocolCraft::ReadData<ProtocolCraft::VarInt>(read_iter, max_length);

    std::shared_ptr<ProtocolCraft::Message> msg;

    if (from == Endpoint::Client)
    {
        msg = ProtocolCraft::MessageFactory::CreateMessageServerbound(minecraftID, connection_state);
    }
    else if (from == Endpoint::Server)
    {
        msg = ProtocolCraft::MessageFactory::CreateMessageClientbound(minecraftID, connection_state);
    }

    if (msg != nullptr)
    {
        bool error_parsing = false;
        try
        {
            msg->Read(read_iter, max_length);
        }
        catch (const std::exception & ex)
        {
            std::cout << ((from == Endpoint::Server) ? "Server --> Client: " : "Client --> Server: ") <<
                "PARSING EXCEPTION: " << ex.what() << " || " << msg->GetName() << std::endl;
            error_parsing = true;
        }
        
        if (!error_parsing)
        {
            // Log the message
            logger.Log(msg, connection_state, from);
            replay_logger.Log(msg, connection_state, from);

            // React to the message if necessary
            msg->Dispatch(this);
        }
    }
    else
    {
        std::cout << ((from == Endpoint::Server) ? "Server --> Client: " : "Client --> Server: ") <<
            "NULL MESSAGE WITH ID: " << minecraftID << std::endl;
    }
}

const std::vector<unsigned char> MinecraftProxy::PacketToBytes(const ProtocolCraft::Message& msg)
{
    std::vector<unsigned char> content;
    msg.Write(content);

    if (compression_threshold != -1)
    {
        if (content.size() < compression_threshold)
        {
            content.insert(content.begin(), 0x00);

        }
        else
        {
            std::vector<unsigned char> compressed_data = Compress(content);
            content.clear();
            ProtocolCraft::WriteData<ProtocolCraft::VarInt>(content.size(), content);
            content.insert(content.end(), compressed_data.begin(), compressed_data.end());
        }
    }

    std::vector<unsigned char> sized_packet;
    ProtocolCraft::WriteData<ProtocolCraft::VarInt>(content.size(), sized_packet);
    sized_packet.insert(sized_packet.end(), content.begin(), content.end());
    return sized_packet;
}

void MinecraftProxy::SendDataTo(const std::vector<unsigned char>& data, const Endpoint to)
{
    if (to == Endpoint::Server)
    {
        std::lock_guard<std::mutex> lock(output_server_mutex_);
        const bool write_in_progress = !output_server_data_.empty();
        output_server_data_.push_back(data);

        if (!write_in_progress)
        {
            // If we send to the server and encryption is
            // enabled, we need to first encrypt the data
#ifdef USE_ENCRYPTION
            if (encrypter)
            {
                output_server_buffer_ = encrypter->Encrypt(output_server_data_.front());
            }
            else
            {
                output_server_buffer_ = output_server_data_.front();
            }
#else
            output_server_buffer_ = output_server_data_.front();
#endif
            asio::async_write(server_socket_, asio::buffer(output_server_buffer_.data(), output_server_buffer_.size()),
                std::bind(&MinecraftProxy::handle_server_write, this,
                    std::placeholders::_1));
        }
    }
    else
    {
        std::lock_guard<std::mutex> lock(output_client_mutex_);
        const bool write_in_progress = !output_client_data_.empty();
        output_client_data_.push_back(data);

        if (!write_in_progress)
        {
            output_client_buffer_ = output_client_data_.front();
            asio::async_write(client_socket_, asio::buffer(output_client_buffer_.data(), output_client_buffer_.size()),
                std::bind(&MinecraftProxy::handle_client_write, this,
                    std::placeholders::_1));
        }
    }
}

void MinecraftProxy::LoadConfig(const std::string& conf_path)
{
    if (conf_path.empty())
    {
        std::cerr << "Error, empty conf path" << std::endl;
        return;
    }

    std::ifstream file = std::ifstream(conf_path, std::ios::in);
    if (!file.is_open())
    {
        std::cerr << "Error trying to open conf file: " << conf_path << "." << std::endl;
        return;
    }

    nlohmann::json json;

    file >> json;

    if (!json.is_object())
    {
        std::cerr << "Error parsing conf file at " << conf_path << "." << std::endl;
        return;
    }

#ifdef USE_ENCRYPTION
    if (json.contains("Online") && json["Online"].get<bool>())
    {
        authentifier = std::make_unique<Botcraft::Authentifier>();

        const std::string credentials_cache_key = json.contains("MicrosoftAccountCacheKey") ? json["MicrosoftAccountCacheKey"].get<std::string>() : "";

        std::cout << "Trying to authenticate using Microsoft account" << std::endl;
        if (!authentifier->AuthMicrosoft(credentials_cache_key))
        {
            std::cerr << "Error trying to authenticate with Microsoft account" << std::endl;
            throw std::runtime_error("Error trying to authenticate with Microsoft account");
        }
    }
#endif
}

void MinecraftProxy::Handle(ProtocolCraft::Message& msg)
{

}

void MinecraftProxy::Handle(ProtocolCraft::ServerboundClientIntentionPacket& msg)
{
    connection_state = static_cast<ProtocolCraft::ConnectionState>(msg.GetIntention());

    ProtocolCraft::ServerboundClientIntentionPacket replacement_intention_packet;
    replacement_intention_packet.SetIntention(msg.GetIntention());
    replacement_intention_packet.SetProtocolVersion(msg.GetProtocolVersion());
    replacement_intention_packet.SetHostName(server_ip_);
    replacement_intention_packet.SetPort(server_port_);

    const std::vector<unsigned char> replacement_bytes = PacketToBytes(replacement_intention_packet);
    client_replacement_data.insert(client_replacement_data.end(), replacement_bytes.begin(), replacement_bytes.end());
}

void MinecraftProxy::Handle(ProtocolCraft::ServerboundHelloPacket& msg)
{
#ifdef USE_ENCRYPTION
    // Make sure we use the name and the signature key
    // of the profile we auth with
    if (authentifier)
    {
        ProtocolCraft::ServerboundHelloPacket replacement_hello_packet;
#if PROTOCOL_VERSION < 759
        replacement_hello_packet.SetGameProfile(authentifier->GetPlayerDisplayName());
#else
        replacement_hello_packet.SetName(authentifier->GetPlayerDisplayName());

        ProtocolCraft::ProfilePublicKey key;
        key.SetTimestamp(authentifier->GetKeyTimestamp());
        key.SetKey(Botcraft::RSAToBytes(authentifier->GetPublicKey()));
        key.SetSignature(Botcraft::DecodeBase64(authentifier->GetKeySignature()));
        replacement_hello_packet.SetPublicKey(key);
#if PROTOCOL_VERSION > 759
        replacement_hello_packet.SetProfileId(authentifier->GetPlayerUUID());
#endif
#endif

        const std::vector<unsigned char> replacement_bytes = PacketToBytes(replacement_hello_packet);
        client_replacement_data.insert(client_replacement_data.end(), replacement_bytes.begin(), replacement_bytes.end());
    }
#endif
}

void MinecraftProxy::Handle(ProtocolCraft::ClientboundGameProfilePacket& msg)
{
    connection_state = ProtocolCraft::ConnectionState::Play;
}

void MinecraftProxy::Handle(ProtocolCraft::ClientboundLoginCompressionPacket& msg)
{
    compression_threshold = msg.GetCompressionThreshold();
}

void MinecraftProxy::Handle(ProtocolCraft::ClientboundHelloPacket& msg)
{
#ifdef USE_ENCRYPTION
    if (!authentifier)
    {
        std::cerr << "WARNING, trying to connect to a server with encryption enabled\n" <<
            "but impossible without being authenticated." << std::endl;
        throw std::runtime_error("Not authenticated");
    }

    std::unique_ptr<Botcraft::AESEncrypter> encrypter_ = std::make_unique<Botcraft::AESEncrypter>();

    std::vector<unsigned char> raw_shared_secret;
    std::vector<unsigned char> encrypted_shared_secret;

#if PROTOCOL_VERSION < 759
    std::vector<unsigned char> encrypted_nonce;
    encrypter_->Init(msg.GetPublicKey(), msg.GetNonce(),
        raw_shared_secret, encrypted_nonce, encrypted_shared_secret);
#else
    std::vector<unsigned char> salted_nonce_signature;
    long long int salt;
    encrypter_->Init(msg.GetPublicKey(), msg.GetNonce(), authentifier->GetPrivateKey(),
        raw_shared_secret, encrypted_shared_secret,
        salt, salted_nonce_signature);
#endif

    authentifier->JoinServer(msg.GetServerID(), raw_shared_secret, msg.GetPublicKey());

    std::shared_ptr<ProtocolCraft::ServerboundKeyPacket> response_msg = std::make_shared<ProtocolCraft::ServerboundKeyPacket>();
    response_msg->SetKeyBytes(encrypted_shared_secret);
#if PROTOCOL_VERSION < 759
    // Pre-1.19 behaviour, send encrypted nonce
    response_msg->SetNonce(encrypted_token);
#else
    // 1.19+ behaviour, send salted nonce signature
    ProtocolCraft::SaltSignature salt_signature;
    salt_signature.SetSalt(salt);
    salt_signature.SetSignature(salted_nonce_signature);
    response_msg->SetSaltSignature(salt_signature);
#endif

    // Send additional packet only to server on behalf of the client
    SendDataTo(PacketToBytes(*response_msg), Endpoint::Server);

    // Log this additional packet
    logger.Log(response_msg, connection_state, Endpoint::SniffcraftToServer);
    replay_logger.Log(response_msg, connection_state, Endpoint::SniffcraftToServer);

    // Set the encrypter for any future message from the server
    encrypter = std::move(encrypter_);

    // Add only one byte in replacement data to signal that this packet should not be transmitted
    server_replacement_data = { 0x00 };
#else
    std::cerr << "WARNING, trying to connect to a server with encryption enabled\n" <<
        "but sniffcraft was build without encryption support." << std::endl;
    throw std::runtime_error("Not authenticated");
#endif
}
