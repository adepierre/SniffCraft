#include <iostream>

#include <protocolCraft/BinaryReadWrite.hpp>
#include <protocolCraft/PacketFactory.hpp>
#include <protocolCraft/Utilities/Json.hpp>

#ifdef USE_ENCRYPTION
#include <botcraft/Network/AESEncrypter.hpp>
#include <botcraft/Network/Authentifier.hpp>
#if PROTOCOL_VERSION > 758 /* > 1.18.2 */
#include <botcraft/Utilities/StringUtilities.hpp>
#endif
#endif

#include "sniffcraft/Compression.hpp"
#include "sniffcraft/conf.hpp"
#include "sniffcraft/MinecraftProxy.hpp"
#include "sniffcraft/Logger.hpp"
#include "sniffcraft/ReplayModLogger.hpp"
#ifdef USE_ENCRYPTION
#include "sniffcraft/MinecraftEncryptionDataProcessor.hpp"
#endif

using namespace ProtocolCraft;

MinecraftProxy::MinecraftProxy(
    asio::io_context& io_context,
    std::function<void(const std::string&, const int)> transfer_callback_
) : BaseProxy(io_context)
{
    connection_state = ConnectionState::Handshake;
    compression_threshold = -1;

#if PROTOCOL_VERSION > 765 /* > 1.20.4 */
    // If it's a version with transfer packet, store the callback
    transfer_callback = transfer_callback_;
#endif
}

MinecraftProxy::~MinecraftProxy()
{
    if (logger != nullptr)
    {
        logger->Stop();
    }
}

void MinecraftProxy::Start(const std::string& server_address, const unsigned short server_port)
{
    logger = std::make_shared<Logger>();

    std::shared_lock<std::shared_mutex> lock(Conf::conf_mutex);
    const ProtocolCraft::Json::Value conf = Conf::LoadConf();
    if (conf.contains(Conf::replay_log_key) && conf[Conf::replay_log_key].get<bool>())
    {
        replay_logger = std::make_unique<ReplayModLogger>();
        replay_logger->SetServerName(server_address + ":" + std::to_string(server_port));
    }

#ifdef USE_ENCRYPTION
    if (conf.contains(Conf::online_key) && conf[Conf::online_key].get<bool>())
    {
        authentifier = std::make_unique<Botcraft::Authentifier>();

        const std::string credentials_cache_key = conf.contains(Conf::account_cache_key_key) ? conf[Conf::account_cache_key_key].get<std::string>() : "";

        std::cout << "Trying to authenticate using Microsoft account" << std::endl;
        if (!authentifier->AuthMicrosoft(credentials_cache_key))
        {
            std::cerr << "Error trying to authenticate with Microsoft account" << std::endl;
            throw std::runtime_error("Error trying to authenticate with Microsoft account");
        }
    }
#endif

    BaseProxy::Start(server_address, server_port);
}

std::shared_ptr<Logger> MinecraftProxy::GetLogger() const
{
    return logger;
}

size_t MinecraftProxy::ProcessData(const std::vector<unsigned char>::const_iterator& data, const size_t length, const Endpoint source)
{
    Connection& dst_connection = source == Endpoint::Server ? client_connection : server_connection;

    std::vector<unsigned char>::const_iterator data_iterator = data;
    size_t max_length = length;

    const size_t packet_length = Peek(data_iterator, max_length);
    const size_t packet_length_length = length - max_length;

    // We don't have enough data to get packet size
    if (packet_length == 0)
    {
        return 0;
    }
    // We don't have enough data to get a full packet
    if (packet_length > max_length)
    {
        return 0;
    }

    size_t remaining_packet_bytes = packet_length;
    std::vector<unsigned char> uncompressed;
    if (compression_threshold > -1)
    {
        const int data_length = ReadData<VarInt>(data_iterator, remaining_packet_bytes);
        if (data_length != 0)
        {
            uncompressed = Decompress(&(*data_iterator), remaining_packet_bytes);
            data_iterator = uncompressed.begin();
            remaining_packet_bytes = uncompressed.size();
        }
    }

    const int minecraft_id = ReadData<VarInt>(data_iterator, remaining_packet_bytes);

    std::shared_ptr<Packet> packet = source == Endpoint::Client ?
        CreateServerboundPacket(connection_state, minecraft_id) :
        CreateClientboundPacket(connection_state, minecraft_id);

    // Clear the replacement bytes vector
    bool error_parsing = false;
    if (packet != nullptr)
    {
        try
        {
            packet->Read(data_iterator, remaining_packet_bytes);
        }
        catch (const std::exception& ex)
        {
            std::cout << ((source == Endpoint::Server) ? "Server --> Client: " : "Client --> Server: ") <<
                "PARSING EXCEPTION for message " << packet->GetName() << "(: " << minecraft_id << ")" << ex.what() << std::endl;
            error_parsing = true;
        }
    }
    else
    {
        std::cout << ((source == Endpoint::Server) ? "Server --> Client: " : "Client --> Server: ") <<
            "NULL MESSAGE WITH ID: " << minecraft_id << std::endl;
        error_parsing = true;
    }

    transmit_original_packet = true;
    const ConnectionState old_connection_state = connection_state;
    if (!error_parsing)
    {
        // React to the message if necessary
        packet->Dispatch(this);
    }

    // Transfer the data as they came
    if (transmit_original_packet)
    {
        // The packet is transmitted, log it as it is
        if (!error_parsing)
        {
            logger->Log(packet, old_connection_state, source, packet_length + packet_length_length);
            if (replay_logger)
            {
                replay_logger->Log(packet, old_connection_state, source);
            }
        }

        dst_connection.WriteData(&(*data), packet_length + packet_length_length);
    }
    // The packet has been replaced by something else, log it as intercepted by sniffcraft
    else if (!error_parsing)
    {
        // The packet has been replaced, log it as intercepted by sniffcraft
        logger->Log(packet, old_connection_state, source == Endpoint::Server ? Endpoint::ServerToSniffcraft : Endpoint::ClientToSniffcraft, packet_length + packet_length_length);
    }

    // Return the number of bytes we read (or rather should have read in case of error)
    return packet_length + packet_length_length;
}

size_t MinecraftProxy::Peek(std::vector<unsigned char>::const_iterator& data, size_t& length)
{
    try
    {
        return static_cast<size_t>(ReadData<VarInt>(data, length));
    }
    catch (const std::exception&)
    {
        return 0;
    }
}

std::vector<unsigned char> MinecraftProxy::PacketToBytes(const Packet& packet) const
{
    std::vector<unsigned char> content;
    packet.Write(content);

    if (compression_threshold > -1)
    {
        if (content.size() < compression_threshold)
        {
            content.insert(content.begin(), 0x00);

        }
        else
        {
            std::vector<unsigned char> compressed_data = Compress(content);
            const int decompressed_size = static_cast<int>(content.size());
            content.clear();
            WriteData<VarInt>(decompressed_size, content);
            content.insert(content.end(), compressed_data.begin(), compressed_data.end());
        }
    }

    std::vector<unsigned char> sized_packet;
    WriteData<VarInt>(static_cast<int>(content.size()), sized_packet);
    sized_packet.insert(std::end(sized_packet), std::cbegin(content), std::cend(content));
    return sized_packet;
}

void MinecraftProxy::Handle(ServerboundClientIntentionPacket& packet)
{
    if (packet.GetProtocolVersion() != PROTOCOL_VERSION)
    {
        std::cout << "WARNING, Client and Sniffcraft protocol versions are different ("
            << packet.GetProtocolVersion() << " VS " << PROTOCOL_VERSION
            << "). Logged packet details may be wrong"
            << std::endl;
    }

#if PROTOCOL_VERSION > 765 /* > 1.20.4 */
    // Store original hostname and port (used by the client to connect to sniffcraft)
    // They could be needed later for any transfer packet
    sniffcraft_hostname = packet.GetHostName();
    sniffcraft_port = packet.GetPort();
#endif
    transmit_original_packet = false;

    const ConnectionState old_connection_state = connection_state;
    switch (packet.GetIntention())
    {
    case 1: // Status
        connection_state = ConnectionState::Status;
        break;
    case 2: // Login
#if PROTOCOL_VERSION > 765 /* > 1.20.4 */
    case 3: // Transfer
#endif
        connection_state = ConnectionState::Login;
        break;
    default:
        throw std::runtime_error("Unknown connection intent: " + std::to_string(packet.GetIntention()));
        break;
    }

    std::shared_ptr<ServerboundClientIntentionPacket> replacement_intention_packet = std::make_shared<ServerboundClientIntentionPacket>();
    replacement_intention_packet->SetIntention(packet.GetIntention());
    replacement_intention_packet->SetProtocolVersion(packet.GetProtocolVersion());
    std::string new_hostname = server_ip_;
    const size_t old_hostname_strlen = strlen(packet.GetHostName().c_str());
    // Forge adds \0FML\0, \0FML2\0 or \0FML3\0 to the hostname
    // strlen will only count the size until the fist \0
    if (packet.GetHostName().size() > old_hostname_strlen)
    {
        new_hostname += packet.GetHostName().substr(old_hostname_strlen);
    }
    replacement_intention_packet->SetHostName(new_hostname);
    replacement_intention_packet->SetPort(server_port_);

    std::vector<unsigned char> replacement_bytes = PacketToBytes(*replacement_intention_packet);
    server_connection.WriteData(replacement_bytes.data(), replacement_bytes.size());

    // We don't log packet size as it's not really part of the network data
    logger->Log(replacement_intention_packet, old_connection_state, Endpoint::SniffcraftToServer, 0);
    // Don't replay log it as it's serverbound
}

void MinecraftProxy::Handle(ServerboundHelloPacket& packet)
{
#ifdef USE_ENCRYPTION
    if (authentifier == nullptr)
    {
        return;
    }

    transmit_original_packet = false;

    // Make sure we use the name and the signature key
    // of the profile we auth with
    std::shared_ptr<ServerboundHelloPacket> replacement_hello_packet = std::make_shared<ServerboundHelloPacket>();
#if PROTOCOL_VERSION < 759 /* < 1.19 */
    replacement_hello_packet->SetGameProfile(authentifier->GetPlayerDisplayName());
#else
    replacement_hello_packet->SetName_(authentifier->GetPlayerDisplayName());

#if PROTOCOL_VERSION < 761 /* < 1.19.3 */
    ProfilePublicKey key;
    key.SetTimestamp(authentifier->GetKeyTimestamp());
    const std::vector<unsigned char> key_bytes = Botcraft::Utilities::RSAToBytes(authentifier->GetPublicKey());
    if (!packet.GetPublicKey().has_value() || key_bytes != packet.GetPublicKey().value().GetKey())
    {
        std::cerr << "WARNING, public key mismatch between client and sniffcraft.\n"
            << "You might get kicked out if you send a chat message" << std::endl;
    }
    key.SetKey(key_bytes);
    key.SetSignature(Botcraft::Utilities::DecodeBase64(authentifier->GetKeySignature()));
    replacement_hello_packet->SetPublicKey(key);
#endif
#if PROTOCOL_VERSION > 759 /* > 1.19 */
    replacement_hello_packet->SetProfileId(authentifier->GetPlayerUUID());
#endif
#endif

    std::vector<unsigned char> replacement_bytes = PacketToBytes(*replacement_hello_packet);
    server_connection.WriteData(replacement_bytes.data(), replacement_bytes.size());
    // We don't log packet size as it's not really part of the network data
    logger->Log(replacement_hello_packet, connection_state, Endpoint::SniffcraftToServer, 0);
    // Don't replay log it as it's serverbound
#endif
}

#if PROTOCOL_VERSION < 764 /* < 1.20.2 */
void MinecraftProxy::Handle(ClientboundGameProfilePacket& packet)
{
    connection_state = ConnectionState::Play;
}
#endif

void MinecraftProxy::Handle(ClientboundLoginCompressionPacket& packet)
{
    compression_threshold = packet.GetCompressionThreshold();
}

void MinecraftProxy::Handle(ClientboundHelloPacket& packet)
{
#ifdef USE_ENCRYPTION
    if (authentifier == nullptr)
    {
        std::cerr << "WARNING, trying to connect to a server with encryption enabled\n"
            << "but impossible without being authenticated.\n"
            << "Try changing Online to true in sniffcraft conf json file\n"
            << "or check Authenticated in the GUI\n"
            << std::endl;
        throw std::runtime_error("Not authenticated");
    }

    transmit_original_packet = false;

    std::unique_ptr<Botcraft::AESEncrypter> encrypter = std::make_unique<Botcraft::AESEncrypter>();

    std::vector<unsigned char> raw_shared_secret;
    std::vector<unsigned char> encrypted_shared_secret;

#if PROTOCOL_VERSION < 759 /* < 1.19 */
    std::vector<unsigned char> encrypted_nonce;
    encrypter->Init(packet.GetPublicKey(), packet.GetNonce(),
        raw_shared_secret, encrypted_nonce, encrypted_shared_secret);
#elif PROTOCOL_VERSION < 761 /* < 1.19.3 */
    std::vector<unsigned char> salted_nonce_signature;
    long long int salt;
    encrypter->Init(packet.GetPublicKey(), packet.GetNonce(), authentifier->GetPrivateKey(),
        raw_shared_secret, encrypted_shared_secret,
        salt, salted_nonce_signature);
#else
    std::vector<unsigned char> encrypted_challenge;
    encrypter->Init(packet.GetPublicKey(), packet.GetChallenge(),
        raw_shared_secret, encrypted_shared_secret, encrypted_challenge);
#endif

    authentifier->JoinServer(packet.GetServerId(), raw_shared_secret, packet.GetPublicKey());

    std::shared_ptr<ServerboundKeyPacket> response_packet = std::make_shared<ServerboundKeyPacket>();
    response_packet->SetKeyBytes(encrypted_shared_secret);
#if PROTOCOL_VERSION < 759 /* < 1.19 */
    // Pre-1.19 behaviour, send encrypted nonce
    response_packet->SetNonce(encrypted_nonce);
#elif PROTOCOL_VERSION < 761 /* < 1.19.3 */
    // 1.19 - 1.19.2 behaviour, send salted nonce signature
    SaltSignature salt_signature;
    salt_signature.SetSalt(salt);
    salt_signature.SetSignature(salted_nonce_signature);
    response_packet->SetSaltSignature(salt_signature);
#else
    // 1.19.3+ behaviour, back to sending encrypted challenge only
    response_packet->SetEncryptedChallenge(encrypted_challenge);
#endif

    // Send additional packet only to server on behalf of the client
    const std::vector<unsigned char> replacement_bytes = PacketToBytes(*response_packet);
    server_connection.WriteData(replacement_bytes.data(), replacement_bytes.size());

    // We don't log packet size as it's not really part of the network data
    logger->Log(response_packet, connection_state, Endpoint::SniffcraftToServer, 0);

    // Set the encrypter for any future message from the server
    std::unique_ptr<DataProcessor> encryption_data_processor = std::make_unique<MinecraftEncryptionDataProcessor>(encrypter);
    server_connection.SetDataProcessor(encryption_data_processor);

#else
    std::cerr << "WARNING, trying to connect to a server with encryption enabled\n" <<
        "but sniffcraft was built without encryption support." << std::endl;
    throw std::runtime_error("Not authenticated");
#endif
}

#if USE_ENCRYPTION && PROTOCOL_VERSION > 760 /* > 1.19.1/2 */
void MinecraftProxy::Handle(ClientboundLoginPacket& packet)
{
    if (authentifier == nullptr)
    {
        return;
    }

    std::shared_ptr<ServerboundChatSessionUpdatePacket> chat_session_packet = std::make_shared<ServerboundChatSessionUpdatePacket>();
    RemoteChatSessionData chat_session_data;

    ProfilePublicKey key;
    key.SetTimestamp(authentifier->GetKeyTimestamp());
    key.SetKey(Botcraft::Utilities::RSAToBytes(authentifier->GetPublicKey()));
    key.SetSignature(Botcraft::Utilities::DecodeBase64(authentifier->GetKeySignature()));

    chat_session_data.SetProfilePublicKey(key);
    chat_session_uuid = UUID();
    std::mt19937 rnd = std::mt19937(static_cast<unsigned int>(std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count()));
    std::uniform_int_distribution<int> distrib(std::numeric_limits<unsigned char>::min(), std::numeric_limits<unsigned char>::max());
    for (size_t i = 0; i < chat_session_uuid.size(); ++i)
    {
        chat_session_uuid[i] = static_cast<unsigned char>(distrib(rnd));
    }
    chat_session_data.SetUuid(chat_session_uuid);

    chat_session_packet->SetChatSession(chat_session_data);
    std::vector<unsigned char> chat_session_packet_bytes = PacketToBytes(*chat_session_packet);

    server_connection.WriteData(chat_session_packet_bytes.data(), chat_session_packet_bytes.size());

    // We don't log packet size as it's not really part of the network data
    logger->Log(chat_session_packet, connection_state, Endpoint::SniffcraftToServer, 0);
}

void MinecraftProxy::Handle(ServerboundChatPacket& packet)
{
    if (authentifier == nullptr)
    {
        return;
    }

    transmit_original_packet = false;

    // Ugly stuff because there is a GetMessage macro in Windows API somewhere :)
#if _MSC_VER || __MINGW32__
#pragma push_macro("GetMessage")
#undef GetMessage
#endif

    std::shared_ptr<ServerboundChatPacket> replacement_chat_packet = std::make_shared<ServerboundChatPacket>();
    replacement_chat_packet->SetMessage(packet.GetMessage());

    long long int salt, timestamp;
    std::vector<unsigned char> signature;

    const auto [signatures, updates] = chat_context.GetLastSeenMessagesUpdate();
    const int current_message_sent_index = message_sent_index++;
    signature = authentifier->GetMessageSignature(packet.GetMessage(), current_message_sent_index, chat_session_uuid, signatures, salt, timestamp);
    replacement_chat_packet->SetLastSeenMessages(updates);

#if _MSC_VER || __MINGW32__
#pragma pop_macro("GetMessage")
#endif

    if (signature.empty())
    {
        throw std::runtime_error("Empty chat message signature.");
    }
    replacement_chat_packet->SetTimestamp(timestamp);
    replacement_chat_packet->SetSalt(salt);
    replacement_chat_packet->SetSignature(signature);

    const std::vector<unsigned char> replacement_bytes = PacketToBytes(*replacement_chat_packet);
    server_connection.WriteData(replacement_bytes.data(), replacement_bytes.size());
    // We don't log packet size as it's not really part of the network data
    logger->Log(replacement_chat_packet, connection_state, Endpoint::SniffcraftToServer, 0);
}

#if PROTOCOL_VERSION < 766 /* < 1.20.5 */
void MinecraftProxy::Handle(ServerboundChatCommandPacket& packet)
#else
void MinecraftProxy::Handle(ServerboundChatCommandSignedPacket& packet)
#endif
{
    if (authentifier == nullptr)
    {
        return;
    }

    transmit_original_packet = false;

#if PROTOCOL_VERSION < 766 /* < 1.20.5 */
    std::shared_ptr<ServerboundChatCommandPacket> replacement_chat_command = std::make_shared<ServerboundChatCommandPacket>();
#else
    std::shared_ptr<ServerboundChatCommandSignedPacket> replacement_chat_command = std::make_shared<ServerboundChatCommandSignedPacket>();
#endif
    replacement_chat_command->SetCommand(packet.GetCommand());
    replacement_chat_command->SetTimestamp(packet.GetTimestamp());
    replacement_chat_command->SetSalt(packet.GetSalt());
    const auto [signatures, updates] = chat_context.GetLastSeenMessagesUpdate();
    replacement_chat_command->SetLastSeenMessages(updates);
    replacement_chat_command->SetArgumentSignatures(packet.GetArgumentSignatures());

    const std::vector<unsigned char> replacement_bytes = PacketToBytes(*replacement_chat_command);
    server_connection.WriteData(replacement_bytes.data(), replacement_bytes.size());
    // We don't log packet size as it's not really part of the network data
    logger->Log(replacement_chat_command, connection_state, Endpoint::SniffcraftToServer, 0);
}

void MinecraftProxy::Handle(ClientboundPlayerChatPacket& packet)
{
    if (authentifier == nullptr)
    {
        return;
    }

    if (packet.GetSignature().has_value())
    {
        chat_context.AddSeenMessage(std::vector<unsigned char>(packet.GetSignature().value().begin(), packet.GetSignature().value().end()));

        if (chat_context.GetOffset() > 64)
        {
            std::shared_ptr<ServerboundChatAckPacket> ack_packet = std::make_shared<ServerboundChatAckPacket>();
            ack_packet->SetOffset(chat_context.GetAndResetOffset());

            const std::vector<unsigned char> replacement_bytes_ack = PacketToBytes(*ack_packet);
            server_connection.WriteData(replacement_bytes_ack.data(), replacement_bytes_ack.size());
            // We don't log packet size as it's not really part of the network data
            logger->Log(ack_packet, connection_state, Endpoint::SniffcraftToServer, 0);
        }
    }
}
#endif

#if PROTOCOL_VERSION > 763 /* > 1.20.1 */
void MinecraftProxy::Handle(ServerboundLoginAcknowledgedPacket& packet)
{
    connection_state = ConnectionState::Configuration;
}

void MinecraftProxy::Handle(ServerboundFinishConfigurationPacket& packet)
{
    connection_state = ConnectionState::Play;
}

void MinecraftProxy::Handle(ServerboundConfigurationAcknowledgedPacket& packet)
{
    connection_state = ConnectionState::Configuration;
}
#endif

#if PROTOCOL_VERSION > 765 /* > 1.20.4 */
void MinecraftProxy::Handle(ClientboundTransferConfigurationPacket& packet)
{
    transfer_callback(packet.GetHost(), packet.GetPort());
    transmit_original_packet = false;
    std::shared_ptr<ClientboundTransferConfigurationPacket> replacement_transfer_packet = std::make_shared<ClientboundTransferConfigurationPacket>();
    replacement_transfer_packet->SetHost(sniffcraft_hostname);
    replacement_transfer_packet->SetPort(sniffcraft_port);
    const std::vector<unsigned char> replacement_bytes = PacketToBytes(*replacement_transfer_packet);
    client_connection.WriteData(replacement_bytes.data(), replacement_bytes.size());
    // We don't log packet size as it's not really part of the network data
    logger->Log(replacement_transfer_packet, connection_state, Endpoint::SniffcraftToClient, 0);
}

void MinecraftProxy::Handle(ClientboundTransferPacket& packet)
{
    transfer_callback(packet.GetHost(), packet.GetPort());
    transmit_original_packet = false;
    std::shared_ptr<ClientboundTransferPacket> replacement_transfer_packet = std::make_shared<ClientboundTransferPacket>();
    replacement_transfer_packet->SetHost(sniffcraft_hostname);
    replacement_transfer_packet->SetPort(sniffcraft_port);
    const std::vector<unsigned char> replacement_bytes = PacketToBytes(*replacement_transfer_packet);
    client_connection.WriteData(replacement_bytes.data(), replacement_bytes.size());
    // We don't log packet size as it's not really part of the network data
    logger->Log(replacement_transfer_packet, connection_state, Endpoint::SniffcraftToClient, 0);
}
#endif
