#pragma once

#include "sniffcraft/enums.hpp"

#include "protocolCraft/enums.hpp"
#include "protocolCraft/Message.hpp"

#include <chrono>
#include <memory>

struct LogItem
{
    std::shared_ptr<ProtocolCraft::Message> msg;
    std::chrono::time_point<std::chrono::system_clock> date;
    ProtocolCraft::ConnectionState connection_state;
    Endpoint origin;
};
