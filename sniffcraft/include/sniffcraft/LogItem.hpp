#pragma once

#include "sniffcraft/enums.hpp"

#include "protocolCraft/enums.hpp"
#include "protocolCraft/Packet.hpp"

#include <chrono>
#include <memory>

struct LogItem
{
    std::shared_ptr<ProtocolCraft::Packet> packet;
    std::chrono::time_point<std::chrono::system_clock> date;
    ProtocolCraft::ConnectionState connection_state;
    Endpoint origin;
    size_t bandwidth_bytes;
};
