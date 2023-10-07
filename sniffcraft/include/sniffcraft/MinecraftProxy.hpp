#pragma once

#include <protocolCraft/Handler.hpp>
#include <protocolCraft/enums.hpp>

#include "sniffcraft/BaseProxy.hpp"

#ifdef USE_ENCRYPTION
#if PROTOCOL_VERSION > 760 /* > 1.19.1/2 */
#include <botcraft/Network/LastSeenMessagesTracker.hpp>
#endif
namespace Botcraft
{
    class Authentifier;
}
#endif

class Logger;
class ReplayModLogger;

class MinecraftProxy : public BaseProxy, public ProtocolCraft::Handler
{
public:
    MinecraftProxy(asio::io_context& io_context, const std::string& conf_path);
    virtual ~MinecraftProxy();
    
    virtual void Start(const std::string& server_address, const unsigned short server_port) override;

protected:
    virtual size_t ProcessData(const std::vector<unsigned char>::const_iterator& data, const size_t length, const Endpoint source) override;

private:
    /// @brief Check the size of the next MC packet
    /// @param data iterator to the data start
    /// @param length number of available bytes
    /// @return The size of the next packet, or 0 if not enough bytes to read the size
    size_t Peek(std::vector<unsigned char>::const_iterator& data, size_t& length);

    /// @brief Convert a MC packet to bytes vector
    /// @param msg Packet to convert
    /// @return Bytes representation of the packet
    std::vector<unsigned char> PacketToBytes(const ProtocolCraft::Message& msg) const;

    void LoadConfig();

    virtual void Handle(ProtocolCraft::Message& msg) override;
    virtual void Handle(ProtocolCraft::ServerboundClientIntentionPacket& msg) override;
    virtual void Handle(ProtocolCraft::ServerboundHelloPacket& msg) override;
#if PROTOCOL_VERSION < 764 /* < 1.20.2 */
    virtual void Handle(ProtocolCraft::ClientboundGameProfilePacket& msg) override;
#endif
    virtual void Handle(ProtocolCraft::ClientboundLoginCompressionPacket& msg) override;
    virtual void Handle(ProtocolCraft::ClientboundHelloPacket& msg) override;
#if USE_ENCRYPTION && PROTOCOL_VERSION > 760 /* > 1.19.1/2 */
    virtual void Handle(ProtocolCraft::ClientboundLoginPacket& msg) override;
    virtual void Handle(ProtocolCraft::ServerboundChatPacket& msg) override;
    virtual void Handle(ProtocolCraft::ServerboundChatCommandPacket& msg) override;
    virtual void Handle(ProtocolCraft::ClientboundPlayerChatPacket& msg) override;
#endif
#if PROTOCOL_VERSION > 763 /* > 1.20.1 */
    virtual void Handle(ProtocolCraft::ServerboundLoginAcknowledgedPacket& msg) override;
    virtual void Handle(ProtocolCraft::ServerboundFinishConfigurationPacket& msg) override;
    virtual void Handle(ProtocolCraft::ServerboundConfigurationAcknowledgedPacket& msg) override;
#endif

private:
    std::string conf_path_;

    std::unique_ptr<Logger> logger;
    std::unique_ptr<ReplayModLogger> replay_logger;

    ProtocolCraft::ConnectionState connection_state;
    bool transmit_original_packet;
    int compression_threshold;
#ifdef USE_ENCRYPTION
    std::unique_ptr<Botcraft::Authentifier> authentifier;
#if PROTOCOL_VERSION > 760 /* > 1.19.1/2 */
    Botcraft::LastSeenMessagesTracker chat_context;
    ProtocolCraft::UUID chat_session_uuid;
    int message_sent_index;
#endif
#endif
};
