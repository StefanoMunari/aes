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

    // gf_mult_2: * 2 in GF(2^8)
    // m(x): AES irreducible polynomial = (0x1B)
    // see sections: 4.1, 4.2 for further details
    static uint8_t gf_mult_2(uint8_t b) {
        bool high_bit_set = b & 0x80; // flag if highest bit is set
        b <<= 1;
        // XTIMES(b): since overflowed then reduce by m(x)
        if (high_bit_set) b ^= 0x1B;
        return b;
    }

    // see sections: 5.1.3, 4.1, 4.2 for further details
    static
    auto mixcolumns(std::array<uint8_t, STATE_SIZE> state) {
        for (auto i = 0; i < state.size(); i += COLUMN_SIZE) {
            // process by matrix column
            auto c = sub_array<COLUMN_SIZE>(state, i);
            // decomposition of (5.8) from AES spec.
            // in GF(2^8): 3 * b -> b + 2 * b
            // Addition/Subtraction in GF(2^8): + is ^, - is ^
            state[i]   = gf_mult_2(c[0]) ^ c[1]            ^ gf_mult_2(c[1]) ^ c[2]            ^ c[3];
            state[i+1] = c[0]            ^ gf_mult_2(c[1]) ^ c[2]            ^ gf_mult_2(c[2]) ^ c[3];
            state[i+2] = c[0]            ^ c[1]            ^ gf_mult_2(c[2]) ^ c[3]            ^ gf_mult_2(c[3]);
            state[i+3] = c[0]            ^ gf_mult_2(c[0]) ^ c[1]            ^ c[2]            ^ gf_mult_2(c[3]);
        }
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
    cipher__(std::array<uint8_t, STATE_SIZE> state, std::array<uint8_t, EXPANDED_KEY_SIZE(KEY_SIZE)> ex_key)
    {
        const auto round_key_0 = sub_array<STATE_SIZE>(ex_key, 0);
#ifdef DEBUG_FIPS_197_APPENDIX_B
    std::cout << "I  ";
    print_hex(state);
    print_hex(round_key_0);
    std::cout << std::endl;
#endif // DEBUG_FIPS_197_APPENDIX_B
        state = add_round_key(state, round_key_0);
        for (int round = 1; round < NUM_ROUNDS(KEY_SIZE); ++round) {
#ifdef DEBUG_FIPS_197_APPENDIX_B
    std::cout << round << "  ";
    print_hex(state);
#endif // DEBUG_FIPS_197_APPENDIX_B
            state = subbytes(state);
#ifdef DEBUG_FIPS_197_APPENDIX_B
    print_hex(state);
#endif // DEBUG_FIPS_197_APPENDIX_B
            state = shiftrows(state);
#ifdef DEBUG_FIPS_197_APPENDIX_B
    print_hex(state);
#endif // DEBUG_FIPS_197_APPENDIX_B
            state = mixcolumns(state);
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
        }
#ifdef DEBUG_FIPS_197_APPENDIX_B
        std::cout << std::to_string(NUM_ROUNDS(KEY_SIZE)) + " ";
        print_hex(state);
#endif // DEBUG_FIPS_197_APPENDIX_B
        state = subbytes(state);
#ifdef DEBUG_FIPS_197_APPENDIX_B
    print_hex(state);
#endif // DEBUG_FIPS_197_APPENDIX_B
        state = shiftrows(state);
#ifdef DEBUG_FIPS_197_APPENDIX_B
    print_hex(state);
#endif // DEBUG_FIPS_197_APPENDIX_B
        const auto byte_i =  NUM_BYTES_X_ROUND * NUM_ROUNDS(KEY_SIZE);
        const auto round_key_n = sub_array<STATE_SIZE>(ex_key, byte_i);
#ifdef DEBUG_FIPS_197_APPENDIX_B
    print_hex(round_key_n);
    std::cout << std::endl;
#endif // DEBUG_FIPS_197_APPENDIX_B
        state = add_round_key(state, round_key_n);
        return state;
    }

    std::array<uint8_t, STATE_SIZE> cipher_128(std::array<uint8_t, STATE_SIZE> plaintext,
                                               std::array<uint8_t, EXPANDED_KEY_SIZE(16U)> ex_key) {
        return cipher__<16U>(plaintext, ex_key);
    }

    std::array<uint8_t, STATE_SIZE> cipher_192(std::array<uint8_t, STATE_SIZE> plaintext,
                                               std::array<uint8_t, EXPANDED_KEY_SIZE(24U)> ex_key) {
        return cipher__<24U>(plaintext, ex_key);
    }

    std::array<uint8_t, STATE_SIZE> cipher_256(std::array<uint8_t, STATE_SIZE> plaintext,
                                               std::array<uint8_t, EXPANDED_KEY_SIZE(32U)> ex_key) {
        return cipher__<32U>(plaintext, ex_key);
    }
}