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
    MinecraftProxy(
        asio::io_context& io_context,
        std::function<void(const std::string&, const int)> transfer_callback_
    );
    virtual ~MinecraftProxy();

    virtual void Start(const std::string& server_address, const unsigned short server_port) override;

    std::shared_ptr<Logger> GetLogger() const;

protected:
    virtual size_t ProcessData(const std::vector<unsigned char>::const_iterator& data, const size_t length, const Endpoint source) override;

private:
    /// @brief Check the size of the next MC packet
    /// @param data iterator to the data start
    /// @param length number of available bytes
    /// @return The size of the next packet, or 0 if not enough bytes to read the size
    size_t Peek(std::vector<unsigned char>::const_iterator& data, size_t& length);

    /// @brief Convert a MC packet to bytes vector
    /// @param packet Packet to convert
    /// @return Bytes representation of the packet
    std::vector<unsigned char> PacketToBytes(const ProtocolCraft::Packet& packet) const;

    virtual void Handle(ProtocolCraft::ServerboundClientIntentionPacket& packet) override;
    virtual void Handle(ProtocolCraft::ServerboundHelloPacket& packet) override;
#if PROTOCOL_VERSION < 764 /* < 1.20.2 */
    virtual void Handle(ProtocolCraft::ClientboundGameProfilePacket& packet) override;
#endif
    virtual void Handle(ProtocolCraft::ClientboundLoginCompressionPacket& packet) override;
    virtual void Handle(ProtocolCraft::ClientboundHelloPacket& packet) override;
#if USE_ENCRYPTION && PROTOCOL_VERSION > 760 /* > 1.19.1/2 */
    virtual void Handle(ProtocolCraft::ClientboundLoginPacket& packet) override;
    virtual void Handle(ProtocolCraft::ServerboundChatPacket& packet) override;
#if PROTOCOL_VERSION < 766 /* < 1.20.5 */
    virtual void Handle(ProtocolCraft::ServerboundChatCommandPacket& packet) override;
#else
    virtual void Handle(ProtocolCraft::ServerboundChatCommandSignedPacket& packet) override;
#endif
    virtual void Handle(ProtocolCraft::ClientboundPlayerChatPacket& packet) override;
#endif
#if PROTOCOL_VERSION > 763 /* > 1.20.1 */
    virtual void Handle(ProtocolCraft::ServerboundLoginAcknowledgedPacket& packet) override;
    virtual void Handle(ProtocolCraft::ServerboundFinishConfigurationPacket& packet) override;
    virtual void Handle(ProtocolCraft::ServerboundConfigurationAcknowledgedPacket& packet) override;
#endif
#if PROTOCOL_VERSION > 765 /* > 1.20.4 */
    virtual void Handle(ProtocolCraft::ClientboundTransferConfigurationPacket& packet) override;
    virtual void Handle(ProtocolCraft::ClientboundTransferPacket& packet) override;
#endif

private:
#if PROTOCOL_VERSION > 765 /* > 1.20.4 */
    // Hostname and port the real client used to connect to sniffcraft
    // (replaced by the server address and port by sniffcraft)
    std::string sniffcraft_hostname;
    int sniffcraft_port;
    // Callback function to handle transfer packets
    std::function<void(const std::string&, const int)> transfer_callback;
#endif

    std::shared_ptr<Logger> logger;
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
