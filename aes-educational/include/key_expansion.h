#ifndef AESEDU_KEY_EXPANSION_H
#define AESEDU_KEY_EXPANSION_H

#include <cstdint>
#include <array>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <utils.h>

namespace aes_edu::key_expansion
{

    std::array<uint8_t, utils::EXPANDED_KEY_SIZE(16U)>
    expand_128(std::array<uint8_t, 16U> key);

    std::array<uint8_t, utils::EXPANDED_KEY_SIZE(24U)>
    expand_192(std::array<uint8_t, 24U> key);

    std::array<uint8_t, utils::EXPANDED_KEY_SIZE(32U)>
    expand_256(std::array<uint8_t, 32U> key);

    template <std::size_t KEY_SIZE>
    auto expand(std::array<uint8_t, KEY_SIZE> key)
    {
        if constexpr (KEY_SIZE == 16U)
        {
            return expand_128(key);
        }
        else if constexpr (KEY_SIZE == 24U)
        {
            return expand_192(key);
        }
        else if constexpr (KEY_SIZE == 32U)
        {
            return expand_256(key);
        }
        else
        {
            throw std::invalid_argument("Invalid KEY_SIZE");
        }
    }
} // key_expansion

#endif //AESEDU_KEY_EXPANSION_H
