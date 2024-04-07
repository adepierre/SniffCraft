#include <array>
#pragma once

#include <string_view>
#include <tuple>

struct NameID
{
    std::string_view name;
    int id;
};

template <typename T>
struct PacketNameIdExtractor {
    static constexpr NameID name_id{ T::packet_name, T::packet_id };
};

template <typename... Ts>
struct PacketNameIdExtractor<std::tuple<Ts...>> {
    static constexpr std::array<NameID, sizeof...(Ts)> name_ids = { PacketNameIdExtractor<Ts>::name_id... };
};
