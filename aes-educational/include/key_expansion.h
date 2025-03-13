#ifndef AESEDU_KEY_EXPANSION_H
#define AESEDU_KEY_EXPANSION_H

#include <cstdint>
#include <array>
#include <iostream>
#include <fstream>
#include <iomanip>

namespace aes_edu::key_expansion
{
    static constexpr uint8_t WORD_SIZE = 4U;
    static constexpr auto NUM_WORDS_X_ROUND = 4U;

    static constexpr uint8_t NUM_ROUNDS(uint8_t key_size)
    {
        switch (key_size)
        {
        case 16U:
            return 10U;
        case 24U:
            return 12U;
        case 32U:
            return 14U;
        default:
            return 0; // invalid size
        }
    }

    static constexpr auto EXPANDED_KEY_SIZE(size_t key_size)
    {
        return key_size + NUM_WORDS_X_ROUND * NUM_ROUNDS(key_size) * WORD_SIZE;
    }

    std::array<uint8_t, EXPANDED_KEY_SIZE(16U)>
    expand_128(std::array<uint8_t, 16U> key);

    std::array<uint8_t, EXPANDED_KEY_SIZE(24U)>
    expand_192(std::array<uint8_t, 24U> key);

    std::array<uint8_t, EXPANDED_KEY_SIZE(32U)>
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
