#include "key_expansion.h"
#include "utils.h"
#include <cstdint>
#include <cstring>
#include <array>
#include <iostream>
#include <fstream>
#include <iomanip>

namespace aes_edu::key_expansion
{
    using namespace utils;
    using aes_word_t = std::array<uint8_t, WORD_SIZE>;

    // round constants
    static constexpr auto NUM_RCON_WORDS = 10U;
    static constexpr std::array<aes_word_t, NUM_RCON_WORDS> RCON = {
        aes_word_t{0x01, 0x00, 0x00, 0x00},
        aes_word_t{0x02, 0x00, 0x00, 0x00},
        aes_word_t{0x04, 0x00, 0x00, 0x00},
        aes_word_t{0x08, 0x00, 0x00, 0x00},
        aes_word_t{0x10, 0x00, 0x00, 0x00},
        aes_word_t{0x20, 0x00, 0x00, 0x00},
        aes_word_t{0x40, 0x00, 0x00, 0x00},
        aes_word_t{0x80, 0x00, 0x00, 0x00},
        aes_word_t{0x1B, 0x00, 0x00, 0x00},
        aes_word_t{0x36, 0x00, 0x00, 0x00}
    };

    static
    auto subword(aes_word_t w)
    {
        return aes_word_t{
            SBOX[w[0]],
            SBOX[w[1]],
            SBOX[w[2]],
            SBOX[w[3]]
        };
    }

    static
    auto rotword(aes_word_t w)
    {
        const auto x = w[0];

        for (auto i = 0; i < WORD_SIZE - 1; ++i)
            w[i] = w[i + 1];

        w[WORD_SIZE - 1] = x;

        return w;
    }


    static
    auto rcon(uint8_t w_i)
    {
        return RCON[w_i];
    }

    static
    auto XOR(aes_word_t x, aes_word_t y)
    {
        return aes_word_t{
            static_cast<uint8_t>(x[0] ^ y[0]),
            static_cast<uint8_t>(x[1] ^ y[1]),
            static_cast<uint8_t>(x[2] ^ y[2]),
            static_cast<uint8_t>(x[3] ^ y[3])
        };
    }

    template <std::size_t KEY_SIZE>
    static
    std::array<uint8_t, EXPANDED_KEY_SIZE(KEY_SIZE)> expand__(std::array<uint8_t, KEY_SIZE> key)
    {
        constexpr auto EXPANDED_KEY_NUM_WORDS = NUM_WORDS_X_ROUND * NUM_ROUNDS(KEY_SIZE); // Nr in words
        std::array<uint8_t, EXPANDED_KEY_SIZE(KEY_SIZE)> ex_key{}; // expanded key

        // 1st round
        memcpy(ex_key.data(), key.data(), KEY_SIZE); // original key
        constexpr auto KEY_NUM_WORDS = KEY_SIZE / WORD_SIZE;
        int w_i = KEY_NUM_WORDS; // word index

        // Nr + 4 rounds to fill expanded key
        while (w_i < EXPANDED_KEY_NUM_WORDS + 4)
        {
            // get next word to process w[i-1]
            aes_word_t temp{};
            memcpy(temp.data(), &ex_key[w_i * WORD_SIZE - WORD_SIZE], WORD_SIZE);
            const auto module = (w_i % KEY_NUM_WORDS);
#ifdef DEBUG_FIPS_197_APPENDIX_A
    std::cout << w_i << " ";
    print_hex(temp);
#endif // DEBUG_FIPS_197_APPENDIX_A
            if (module == 0)
            {
                auto r = rotword(temp);
                auto s = subword(r);
                auto c = rcon((w_i - 1) / KEY_NUM_WORDS);
                temp = XOR(s, c);
#ifdef DEBUG_FIPS_197_APPENDIX_A
        print_hex(r);
        print_hex(s);
        print_hex(c);
        print_hex(temp);
#endif // DEBUG_FIPS_197_APPENDIX_A
            }
            else if (KEY_NUM_WORDS > 6 && (module == WORD_SIZE))
            {
                temp = subword(temp);
            }
            // get word to be xored w[i-Nk]
            aes_word_t w{};
            memcpy(w.data(), &ex_key[(w_i * WORD_SIZE - KEY_NUM_WORDS * WORD_SIZE)], WORD_SIZE);
            // compute result word for this round
            auto result = XOR(w, temp);
            // update expanded key
            memcpy(&ex_key[w_i * WORD_SIZE], result.data(), WORD_SIZE);
            ++w_i;
#ifdef DEBUG_FIPS_197_APPENDIX_A
    print_hex(w);
    print_hex(result);
    std::cout << std::endl;
#endif // DEBUG_FIPS_197_APPENDIX_A
        }
        return ex_key;
    }

    std::array<uint8_t, EXPANDED_KEY_SIZE(16U)>
    expand_128(std::array<uint8_t, 16U> key)
    {
        return expand__(key);
    }

    std::array<uint8_t, EXPANDED_KEY_SIZE(24U)>
    expand_192(std::array<uint8_t, 24U> key)
    {
        return expand__(key);
    }

    std::array<uint8_t, EXPANDED_KEY_SIZE(32U)>
    expand_256(std::array<uint8_t, 32U> key)
    {
        return expand__(key);
    }
} // key_expansion
