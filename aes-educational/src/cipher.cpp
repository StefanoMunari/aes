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
        std::function<std::array<uint8_t, ROW_SIZE>(int)>
        get_row_indexes = [&](int start) -> std::array<uint8_t, ROW_SIZE>
        {
      		const auto offset = WORD_SIZE;
      		std::array<uint8_t, ROW_SIZE> row_indexes{};
        	for (int i = 0; i < ROW_SIZE; ++i) row_indexes[i] = start + offset * i;
            return row_indexes;
        };
        // row: 0 -> skip
        // row 1
        auto row_i = 1;
        auto row_indexes = get_row_indexes(row_i);
        auto x = state[row_i];
        for (int i = 0; i < ROW_SIZE; ++i) state[row_indexes[i]] = state[row_indexes[((i+row_i) % ROW_SIZE)]];
        state[row_indexes[ROW_SIZE-row_i]] = x;
        // row 2
        row_i = 2;
        row_indexes = get_row_indexes(row_i);
        for (int i = 0; i < ROW_SIZE/2; ++i) {
			auto x = state[row_indexes[i]];
			state[row_indexes[i]] = state[row_indexes[i+row_i]];
			state[row_indexes[i+row_i]] = x;
        }
        // row 3
        row_i = 3;
        row_indexes = get_row_indexes(row_i);
        x = state[row_indexes[ROW_SIZE-1]];
        for (int i = ROW_SIZE-1; i > 0; --i) state[row_indexes[i]] = state[row_indexes[i-1]];
        state[row_indexes[0]] = x;

        return state;
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