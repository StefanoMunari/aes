#include "cipher.h"
#include "utils.h"
#include <functional>

namespace aes_edu::cipher {
    using namespace utils;

    static
    auto subbytes(std::array<uint8_t, STATE_SIZE> state) {
        std::array<uint8_t, STATE_SIZE> s {};
        for (int i = 0; i < state.size(); ++i)
        {
            s[i] = SBOX[state[i]];
        }
        return s;
    }

    static
    auto shiftrows(std::array<uint8_t, STATE_SIZE> state)
    {
        std::function<std::array<uint8_t, STATE_SIZE>(std::array<uint8_t, STATE_SIZE>, int)>
        shiftrow = [&](std::array<uint8_t, STATE_SIZE> state, int start) -> std::array<uint8_t, STATE_SIZE>
        {
            if (start == WORD_SIZE) return state;// last row processed
            auto offset = WORD_SIZE;
            auto x = state[start];
            const auto end_i = start + offset * (WORD_SIZE - 1);
            for (int i = start + offset; i <= end_i; i += offset) state[i-offset] = state[i];
            state[end_i] = x;
            return shiftrow(state, start + 1);
        };
        // row: 1 -> skip
        // row: 2, 3, 4
        return shiftrow(state, 1);
    }

    static
    auto mixcolumns(std::array<uint8_t, STATE_SIZE> state) {
        return state;
    }

    static
    auto add_round_key(std::array<uint8_t, STATE_SIZE> state, const std::array<uint8_t, STATE_SIZE> round_key) {
      	std::transform(state.begin(), state.end(), round_key.begin(), state.begin(),
        [](uint8_t x, uint8_t y) {
            return x ^= y;
        });
        return state;
    }

    template <std::size_t KEY_SIZE>
    static
    std::array<uint8_t, STATE_SIZE>
    cipher__(uint8_t *plaintext, const size_t plaintext_size,
        std::array<uint8_t, EXPANDED_KEY_SIZE(KEY_SIZE)> ex_key)
    {
        std::array<uint8_t, STATE_SIZE> state = {};
        memcpy(state.data(), plaintext, STATE_SIZE);
        const auto round_key_0 = sub_array(ex_key, 0);
        state = add_round_key(state, round_key_0);
        for (int round = 0; round < NUM_ROUNDS(KEY_SIZE) - 1; ++round) {
            state = subbytes(state);
            state = shiftrows(state);
            state = mixcolumns(state);
            const auto byte_i = NUM_WORDS_X_ROUND * round;
            const auto round_key = sub_array(ex_key, byte_i);
            state = add_round_key(state, round_key);
        }
        state = subbytes(state);
        state = shiftrows(state);
        const auto byte_i = NUM_WORDS_X_ROUND * NUM_ROUNDS(KEY_SIZE);
        const auto round_key_n = sub_array(ex_key, byte_i);
        state = add_round_key(state, round_key_n);
        return state;
    }

    std::array<uint8_t, STATE_SIZE> cipher_128(uint8_t *plaintext, const size_t plaintext_size,
    std::array<uint8_t, EXPANDED_KEY_SIZE(16U)> ex_key) {
        return cipher__<16U>(plaintext, plaintext_size, ex_key);
    }

    std::array<uint8_t, STATE_SIZE> cipher_192(uint8_t *plaintext, const size_t plaintext_size,
        std::array<uint8_t, EXPANDED_KEY_SIZE(24U)> ex_key) {
        return cipher__<24U>(plaintext, plaintext_size, ex_key);
    }

    std::array<uint8_t, STATE_SIZE> cipher_256(uint8_t *plaintext, const size_t plaintext_size,
        std::array<uint8_t, EXPANDED_KEY_SIZE(32U)> ex_key) {
        return cipher__<32U>(plaintext, plaintext_size, ex_key);
    }
}