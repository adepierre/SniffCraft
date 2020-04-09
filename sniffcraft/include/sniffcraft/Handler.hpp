#pragma once

#include <protocolCraft/Handler.hpp>
#include <protocolCraft/AllMessages.hpp>

namespace ProtocolCraft
{
    class Handler : public GenericHandler<Message, AllMessages> {};
}
