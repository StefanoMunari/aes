#include "inv_cipher.h"
#include "utils.h"
#include "common.h"
#include "constants.h"
#include <functional>

namespace aes_edu::inv_cipher {
    using namespace utils;
    using namespace common;
    using namespace constants;

    static
    auto inv_shiftrows(std::array<uint8_t, STATE_SIZE> state) {
        // row: 0 -> skip
        // row 1
        auto row_i = 1;
        auto row_indexes = get_row_indexes(row_i);
        auto x = state[row_indexes[ROW_SIZE-1]];
        for (int i = ROW_SIZE-2; i >= 0; --i) state[row_indexes[i+1]] = state[row_indexes[i]];
        state[row_indexes[0]] = x;
        // row 2
        row_i = 2;
        row_indexes = get_row_indexes(row_i);
        x = state[row_indexes[0]];
        state[row_indexes[0]] = state[row_indexes[2]];
        state[row_indexes[2]] = x;
        x = state[row_indexes[1]];
        state[row_indexes[1]] = state[row_indexes[ROW_SIZE-1]];
        state[row_indexes[ROW_SIZE-1]] = x;
        // row 3
        row_i = 3;
        row_indexes = get_row_indexes(row_i);
        x = state[row_indexes[0]];
        for (int i = 0; i < (ROW_SIZE - 1); ++i) state[row_indexes[i]] = state[row_indexes[i+1]];
        state[row_indexes[ROW_SIZE-1]] = x;

        return state;
    }

    static
    auto inv_subbytes(std::array<uint8_t, STATE_SIZE> state) {
        return substitution(state, (uint8_t *)INV_SBOX);
    }

    template <std::size_t KEY_SIZE>
    static
    std::array<uint8_t, STATE_SIZE>
    inv_cipher__(std::array<uint8_t, STATE_SIZE> state, std::array<uint8_t, EXPANDED_KEY_SIZE(KEY_SIZE)> ex_key)
    {
        const auto byte_i = NUM_BYTES_X_ROUND * NUM_ROUNDS(KEY_SIZE);
        const auto round_key_n = sub_array<STATE_SIZE>(ex_key, byte_i);
        state = add_round_key(state, round_key_n);
        for (int round = NUM_ROUNDS(KEY_SIZE); round > 0; --round) {
            state = inv_shiftrows(state);
            state = inv_subbytes(state);
            const auto byte_i = NUM_BYTES_X_ROUND * round;
            const auto round_key = sub_array<STATE_SIZE>(ex_key, byte_i);
            state = add_round_key(state, round_key);
            //state = inv_mixcolumns(state);
        }
        state = inv_shiftrows(state);
        state = inv_subbytes(state);
        const auto round_key_0 = sub_array<STATE_SIZE>(ex_key, 0);
        state = add_round_key(state, round_key_0);
        return state;
    }

    std::array<uint8_t, STATE_SIZE> inv_cipher_128(std::array<uint8_t, STATE_SIZE> plaintext,
                                               std::array<uint8_t, EXPANDED_KEY_SIZE(16U)> ex_key) {
        return inv_cipher__<16U>(plaintext, ex_key);
    }

    std::array<uint8_t, STATE_SIZE> inv_cipher_192(std::array<uint8_t, STATE_SIZE> plaintext,
                                               std::array<uint8_t, EXPANDED_KEY_SIZE(24U)> ex_key) {
        return inv_cipher__<24U>(plaintext, ex_key);
    }

    std::array<uint8_t, STATE_SIZE> inv_cipher_256(std::array<uint8_t, STATE_SIZE> plaintext,
                                               std::array<uint8_t, EXPANDED_KEY_SIZE(32U)> ex_key) {
        return inv_cipher__<32U>(plaintext, ex_key);
    }
}