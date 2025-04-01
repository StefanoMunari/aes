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

    // gf_mult: a * b in GF(2^8)
    // m(x): AES irreducible polynomial = (0x1B)
    // see sections: 4.1, 4.2, 4.3, 4.4 for further details
    static uint8_t gmul(uint8_t a, uint8_t b) {
        uint8_t x = 0x00;
        for (int i=0; i < 8; ++i) {
            bool low_bit_set = a & 0x01; // flag if lowest bit is set
            if (low_bit_set) x ^= b;
            a >>= 1;
            bool high_bit_set = b & 0x80; // flag if highest bit is set
            b <<= 1;
            // XTIMES(b): since overflowed then reduce by m(x)
            if (high_bit_set) b ^= 0x1B;
        }
        return x;
    }

    static
    auto inv_mixcolumns(std::array<uint8_t, STATE_SIZE> state) {
        for (auto i = 0; i < state.size(); i += COLUMN_SIZE) {
            auto c = sub_array<COLUMN_SIZE>(state, i);

            state[i]   = gmul(c[0], 0x0E) ^ gmul(c[1], 0x0B) ^ gmul(c[2], 0x0D) ^ gmul(c[3], 0x09);
            state[i+1] = gmul(c[0], 0x09) ^ gmul(c[1], 0x0E) ^ gmul(c[2], 0x0B) ^ gmul(c[3], 0x0D);
            state[i+2] = gmul(c[0], 0x0D) ^ gmul(c[1], 0x09) ^ gmul(c[2], 0x0E) ^ gmul(c[3], 0x0B);
            state[i+3] = gmul(c[0], 0x0B) ^ gmul(c[1], 0x0D) ^ gmul(c[2], 0x09) ^ gmul(c[3], 0x0E);
        }
        return state;
    }

    template <std::size_t KEY_SIZE>
    static
    std::array<uint8_t, STATE_SIZE>
    inv_cipher__(std::array<uint8_t, STATE_SIZE> state, std::array<uint8_t, EXPANDED_KEY_SIZE(KEY_SIZE)> ex_key)
    {
        const auto byte_i = NUM_BYTES_X_ROUND * NUM_ROUNDS(KEY_SIZE);
        const auto round_key_n = sub_array<STATE_SIZE>(ex_key, byte_i);
#ifdef DEBUG_FIPS_197_APPENDIX_B
        std::cout << "I  ";
        print_hex(state);
        print_hex(round_key_n);
        std::cout << std::endl;
#endif // DEBUG_FIPS_197_APPENDIX_B
        state = add_round_key(state, round_key_n);
        for (int round = NUM_ROUNDS(KEY_SIZE) - 1; round > 0; --round) {
#ifdef DEBUG_FIPS_197_APPENDIX_B
            std::cout << round << "  ";
            print_hex(state);
#endif // DEBUG_FIPS_197_APPENDIX_B
            state = inv_shiftrows(state);
#ifdef DEBUG_FIPS_197_APPENDIX_B
            print_hex(state);
#endif // DEBUG_FIPS_197_APPENDIX_B
            state = inv_subbytes(state);
#ifdef DEBUG_FIPS_197_APPENDIX_B
            print_hex(state);
#endif // DEBUG_FIPS_197_APPENDIX_B
            const auto byte_i = NUM_BYTES_X_ROUND * round;
            const auto round_key = sub_array<STATE_SIZE>(ex_key, byte_i);
#ifdef DEBUG_FIPS_197_APPENDIX_B
            print_hex(round_key);
            std::cout << std::endl;
#endif // DEBUG_FIPS_197_APPENDIX_B
            state = add_round_key(state, round_key);
            state = inv_mixcolumns(state);
        }
#ifdef DEBUG_FIPS_197_APPENDIX_B
        std::cout << "0 ";
        print_hex(state);
#endif // DEBUG_FIPS_197_APPENDIX_B
        state = inv_shiftrows(state);
#ifdef DEBUG_FIPS_197_APPENDIX_B
        print_hex(state);
#endif // DEBUG_FIPS_197_APPENDIX_B
        state = inv_subbytes(state);
#ifdef DEBUG_FIPS_197_APPENDIX_B
        print_hex(state);
#endif // DEBUG_FIPS_197_APPENDIX_B
        const auto round_key_0 = sub_array<STATE_SIZE>(ex_key, 0);
#ifdef DEBUG_FIPS_197_APPENDIX_B
        print_hex(round_key_0);
        std::cout << std::endl;
#endif // DEBUG_FIPS_197_APPENDIX_B
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