#include <iostream>

#include <protocolCraft/BinaryReadWrite.hpp>
#include <protocolCraft/MessageFactory.hpp>
#include <protocolCraft/Utilities/Json.hpp>

#ifdef USE_ENCRYPTION
#include <botcraft/Network/AESEncrypter.hpp>
#include <botcraft/Network/Authentifier.hpp>
#if PROTOCOL_VERSION > 760
#include <botcraft/Utilities/StringUtilities.hpp>
#endif
#endif

#include "sniffcraft/Compression.hpp"
#include "sniffcraft/MinecraftProxy.hpp"
#include "sniffcraft/Logger.hpp"
#include "sniffcraft/ReplayModLogger.hpp"
#ifdef USE_ENCRYPTION
#include "sniffcraft/MinecraftEncryptionDataProcessor.hpp"
#endif

using namespace ProtocolCraft;

MinecraftProxy::MinecraftProxy(asio::io_context& io_context, const std::string& conf_path) :
    BaseProxy(io_context)
{
    connection_state = ConnectionState::Handshake;
    compression_threshold = -1;
    conf_path_ = conf_path;
}

MinecraftProxy::~MinecraftProxy()
{

}

void MinecraftProxy::Start(const std::string& server_address, const unsigned short server_port)
{
    logger = std::make_unique<Logger>(conf_path_);
    replay_logger = nullptr;

    LoadConfig();

    BaseProxy::Start(server_address, server_port);
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

    std::shared_ptr<Message> msg = source == Endpoint::Client ?
        CreateServerboundMessage(connection_state, minecraft_id) :
        CreateClientboundMessage(connection_state, minecraft_id);

    // Clear the replacement bytes vector
    bool error_parsing = false;
    if (msg != nullptr)
    {
        try
        {
            msg->Read(data_iterator, remaining_packet_bytes);
        }
        catch (const std::exception& ex)
        {
            std::cout << ((source == Endpoint::Server) ? "Server --> Client: " : "Client --> Server: ") <<
                "PARSING EXCEPTION: " << ex.what() << " || " << msg->GetName() << std::endl;
            error_parsing = true;
        }
    }
    else
    {
        std::cout << ((source == Endpoint::Server) ? "Server --> Client: " : "Client --> Server: ") <<
            "NULL MESSAGE WITH ID: " << minecraft_id << std::endl;
    }

    transmit_original_packet = true;
    if (!error_parsing)
    {
        // React to the message if necessary
        msg->Dispatch(this);
    }

    // Transfer the data as they came
    if (transmit_original_packet)
    {
        // The packet is transmitted, log it as it is
        if (!error_parsing)
        {
            logger->Log(msg, connection_state, source);
            if (replay_logger)
            {
                replay_logger->Log(msg, connection_state, source);
            }
        }

        dst_connection.WriteData(&(*data), packet_length + packet_length_length);
    }
    // The packet has been replaced by something else, log it as intercepted by sniffcraft
    else if (!error_parsing)
    {
        // The packet has been replaced, log it as intercepted by sniffcraft
        logger->Log(msg, connection_state, source == Endpoint::Server ? Endpoint::ServerToSniffcraft : Endpoint::ClientToSniffcraft);
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

std::vector<unsigned char> MinecraftProxy::PacketToBytes(const Message& msg) const
{
    std::vector<unsigned char> content;
    msg.Write(content);

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

void MinecraftProxy::LoadConfig()
{
    if (conf_path_.empty())
    {
        std::cerr << "Error, empty conf path" << std::endl;
        return;
    }

    std::ifstream file = std::ifstream(conf_path_, std::ios::in);
    if (!file.is_open())
    {
        std::cerr << "Error trying to open conf file: " << conf_path_ << "." << std::endl;
        return;
    }

    Json::Value json;
    file >> json;
    file.close();

    if (!json.is_object())
    {
        std::cerr << "Error parsing conf file at " << conf_path_ << "." << std::endl;
        return;
    }

    if (json.contains("LogToReplay") && json["LogToReplay"].get<bool>())
    {
        replay_logger = std::make_unique<ReplayModLogger>(conf_path_);
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

void MinecraftProxy::Handle(Message& msg)
{

}

void MinecraftProxy::Handle(ServerboundClientIntentionPacket& msg)
{
    transmit_original_packet = false;

    connection_state = static_cast<ConnectionState>(msg.GetIntention());

    std::shared_ptr<ServerboundClientIntentionPacket> replacement_intention_packet = std::make_shared<ServerboundClientIntentionPacket>();
    replacement_intention_packet->SetIntention(msg.GetIntention());
    replacement_intention_packet->SetProtocolVersion(msg.GetProtocolVersion());
    replacement_intention_packet->SetHostName(server_ip_);
    replacement_intention_packet->SetPort(server_port_);

    std::vector<unsigned char> replacement_bytes = PacketToBytes(*replacement_intention_packet);
    server_connection.WriteData(replacement_bytes.data(), replacement_bytes.size());

    logger->Log(replacement_intention_packet, connection_state, Endpoint::SniffcraftToServer);
    // Don't replay log it as it's serverbound
}

void MinecraftProxy::Handle(ServerboundHelloPacket& msg)
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
#if PROTOCOL_VERSION < 759
    replacement_hello_packet->SetGameProfile(authentifier->GetPlayerDisplayName());
#else
    replacement_hello_packet->SetName(authentifier->GetPlayerDisplayName());

#if PROTOCOL_VERSION < 761
    ProfilePublicKey key;
    key.SetTimestamp(authentifier->GetKeyTimestamp());
    const std::vector<unsigned char> key_bytes = Botcraft::RSAToBytes(authentifier->GetPublicKey());
    if (key_bytes != msg.GetPublicKey().GetKey())
    {
        std::cerr << "WARNING, public key mismatch between client and sniffcraft.\n"
            << "You might get kicked out if you send a chat message" << std::endl;
    }
    key.SetKey(key_bytes);
    key.SetSignature(Botcraft::DecodeBase64(authentifier->GetKeySignature()));
    replacement_hello_packet->SetPublicKey(key);
#endif
#if PROTOCOL_VERSION > 759
    replacement_hello_packet->SetProfileId(authentifier->GetPlayerUUID());
#endif
#endif

    std::vector<unsigned char> replacement_bytes = PacketToBytes(*replacement_hello_packet);
    server_connection.WriteData(replacement_bytes.data(), replacement_bytes.size());
    logger->Log(replacement_hello_packet, connection_state, Endpoint::SniffcraftToServer);
    // Don't replay log it as it's serverbound
#endif
}

void MinecraftProxy::Handle(ClientboundGameProfilePacket& msg)
{
    connection_state = ConnectionState::Play;
}

void MinecraftProxy::Handle(ClientboundLoginCompressionPacket& msg)
{
    compression_threshold = msg.GetCompressionThreshold();
}

void MinecraftProxy::Handle(ClientboundHelloPacket& msg)
{
#ifdef USE_ENCRYPTION
    if (authentifier == nullptr)
    {
        std::cerr << "WARNING, trying to connect to a server with encryption enabled\n"
            << "but impossible without being authenticated.\n"
            << "Try changing Online to true in sniffcraft conf json file"
            << std::endl;
        throw std::runtime_error("Not authenticated");
    }

    transmit_original_packet = false;

    std::unique_ptr<Botcraft::AESEncrypter> encrypter = std::make_unique<Botcraft::AESEncrypter>();

    std::vector<unsigned char> raw_shared_secret;
    std::vector<unsigned char> encrypted_shared_secret;

#if PROTOCOL_VERSION < 759
    std::vector<unsigned char> encrypted_nonce;
    encrypter->Init(msg.GetPublicKey(), msg.GetNonce(),
        raw_shared_secret, encrypted_nonce, encrypted_shared_secret);
#elif PROTOCOL_VERSION < 761
    std::vector<unsigned char> salted_nonce_signature;
    long long int salt;
    encrypter->Init(msg.GetPublicKey(), msg.GetNonce(), authentifier->GetPrivateKey(),
        raw_shared_secret, encrypted_shared_secret,
        salt, salted_nonce_signature);
#else
    std::vector<unsigned char> encrypted_challenge;
    encrypter->Init(msg.GetPublicKey(), msg.GetChallenge(),
        raw_shared_secret, encrypted_shared_secret, encrypted_challenge);
#endif

    authentifier->JoinServer(msg.GetServerID(), raw_shared_secret, msg.GetPublicKey());

    std::shared_ptr<ServerboundKeyPacket> response_msg = std::make_shared<ServerboundKeyPacket>();
    response_msg->SetKeyBytes(encrypted_shared_secret);
#if PROTOCOL_VERSION < 759
    // Pre-1.19 behaviour, send encrypted nonce
    response_msg->SetNonce(encrypted_nonce);
#elif PROTOCOL_VERSION < 761
    // 1.19 - 1.19.2 behaviour, send salted nonce signature
    SaltSignature salt_signature;
    salt_signature.SetSalt(salt);
    salt_signature.SetSignature(salted_nonce_signature);
    response_msg->SetSaltSignature(salt_signature);
#else
    // 1.19.3+ behaviour, back to sending encrypted challenge only
    response_msg->SetEncryptedChallenge(encrypted_challenge);
#endif

    // Send additional packet only to server on behalf of the client
    const std::vector<unsigned char> replacement_bytes = PacketToBytes(*response_msg);
    server_connection.WriteData(replacement_bytes.data(), replacement_bytes.size());

    logger->Log(response_msg, connection_state, Endpoint::SniffcraftToServer);

    // Set the encrypter for any future message from the server
    std::unique_ptr<DataProcessor> encryption_data_processor = std::make_unique<MinecraftEncryptionDataProcessor>(encrypter);
    server_connection.SetDataProcessor(encryption_data_processor);

#else
    std::cerr << "WARNING, trying to connect to a server with encryption enabled\n" <<
        "but sniffcraft was built without encryption support." << std::endl;
    throw std::runtime_error("Not authenticated");
#endif
}

#if USE_ENCRYPTION && PROTOCOL_VERSION > 760
void MinecraftProxy::Handle(ClientboundLoginPacket& msg)
{
    if (authentifier == nullptr)
    {
        return;
    }

    std::shared_ptr<ServerboundChatSessionUpdatePacket> chat_session_msg = std::make_shared<ServerboundChatSessionUpdatePacket>();
    RemoteChatSessionData chat_session_data;

    ProfilePublicKey key;
    key.SetTimestamp(authentifier->GetKeyTimestamp());
    key.SetKey(Botcraft::RSAToBytes(authentifier->GetPublicKey()));
    key.SetSignature(Botcraft::DecodeBase64(authentifier->GetKeySignature()));

    chat_session_data.SetProfilePublicKey(key);
    chat_session_uuid = UUID();
    std::mt19937 rnd = std::mt19937(static_cast<unsigned int>(std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count()));
    std::uniform_int_distribution<int> distrib(std::numeric_limits<unsigned char>::min(), std::numeric_limits<unsigned char>::max());
    for (size_t i = 0; i < chat_session_uuid.size(); ++i)
    {
        chat_session_uuid[i] = static_cast<unsigned char>(distrib(rnd));
    }
    chat_session_data.SetUUID(chat_session_uuid);

    chat_session_msg->SetChatSession(chat_session_data);
    std::vector<unsigned char> chat_session_msg_bytes = PacketToBytes(*chat_session_msg);

    server_connection.WriteData(chat_session_msg_bytes.data(), chat_session_msg_bytes.size());

    logger->Log(chat_session_msg, connection_state, Endpoint::SniffcraftToServer);
}

void MinecraftProxy::Handle(ServerboundChatPacket& msg)
{
    if (authentifier == nullptr)
    {
        return;
    }

    transmit_original_packet = false;

    // Ugly stuff because there is a GetMessage macro in Windows API somewhere :)
#if _MSC_VER
#pragma push_macro("GetMessage")
#undef GetMessage
#endif

    std::shared_ptr<ServerboundChatPacket> replacement_chat_packet = std::make_shared<ServerboundChatPacket>();
    replacement_chat_packet->SetMessage(msg.GetMessage());

    long long int salt, timestamp;
    std::vector<unsigned char> signature;

    const auto [signatures, updates] = chat_context.GetLastSeenMessagesUpdate();
    const int current_message_sent_index = message_sent_index++;
    signature = authentifier->GetMessageSignature(msg.GetMessage(), current_message_sent_index, chat_session_uuid, signatures, salt, timestamp);
    replacement_chat_packet->SetLastSeenMessages(updates);

#if _MSC_VER
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
    logger->Log(replacement_chat_packet, connection_state, Endpoint::SniffcraftToServer);
}

void MinecraftProxy::Handle(ServerboundChatCommandPacket& msg)
{
    if (authentifier == nullptr)
    {
        return;
    }

    transmit_original_packet = false;

    std::shared_ptr<ServerboundChatCommandPacket> replacement_chat_command = std::make_shared<ServerboundChatCommandPacket>();
    replacement_chat_command->SetCommand(msg.GetCommand());
    replacement_chat_command->SetTimestamp(msg.GetTimestamp());
    replacement_chat_command->SetSalt(msg.GetSalt());
    const auto [signatures, updates] = chat_context.GetLastSeenMessagesUpdate();
    replacement_chat_command->SetLastSeenMessages(updates);
    replacement_chat_command->SetArgumentSignatures(msg.GetArgumentSignatures());

    const std::vector<unsigned char> replacement_bytes = PacketToBytes(*replacement_chat_command);
    server_connection.WriteData(replacement_bytes.data(), replacement_bytes.size());
    logger->Log(replacement_chat_command, connection_state, Endpoint::SniffcraftToServer);
}

void MinecraftProxy::Handle(ClientboundPlayerChatPacket& msg)
{
    if (authentifier == nullptr)
    {
        return;
    }

    if (msg.GetSignature().has_value())
    {
        chat_context.AddSeenMessage(msg.GetSignature().value());

        if (chat_context.GetOffset() > 64)
        {
            std::shared_ptr<ServerboundChatAckPacket> ack_msg = std::make_shared<ServerboundChatAckPacket>();
            ack_msg->SetOffset(chat_context.GetAndResetOffset());

            const std::vector<unsigned char> replacement_bytes_ack = PacketToBytes(*ack_msg);
            server_connection.WriteData(replacement_bytes_ack.data(), replacement_bytes_ack.size());
            logger->Log(ack_msg, connection_state, Endpoint::SniffcraftToServer);
        }
    }
}
#endif
