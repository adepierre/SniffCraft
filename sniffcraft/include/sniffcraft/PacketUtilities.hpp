#pragma once

#include <array>
#include <string_view>
#include <tuple>

struct NameID
{
    std::string_view name;
    int id;
};

template <typename Tuple, int... Indices>
constexpr std::array<NameID, sizeof...(Indices)> GetNameIds(std::integer_sequence<int, Indices...> seq)
{
    return { NameID{std::tuple_element_t<Indices, Tuple>::packet_name, Indices} ... };
}

template <typename Tuple>
struct PacketNameIdExtractor{
    static constexpr auto name_ids = GetNameIds<Tuple>(std::make_integer_sequence<int, std::tuple_size_v<Tuple>>{});
};
