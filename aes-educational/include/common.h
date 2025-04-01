#ifndef AESEDU_COMMON_H
#define AESEDU_COMMON_H

#include <array>
#include <cstdint>
#include "constants.h"

namespace aes_edu::common {
    namespace c = constants;

    inline
    auto add_round_key(std::array<uint8_t, c::STATE_SIZE> state, const std::array<uint8_t, c::STATE_SIZE> round_key) {
        std::transform(state.begin(), state.end(), round_key.begin(), state.begin(),
      [](uint8_t x, uint8_t y) {
          return x ^= y;
      });
        return state;
    }

    inline
    auto substitution(std::array<uint8_t, c::STATE_SIZE> state, uint8_t box[]) {
        std::array<uint8_t, c::STATE_SIZE> s {};
        for (int i = 0; i < state.size(); ++i)
        {
            s[i] = box[state[i]];
        }
        return s;
    }

}

#endif //AESEDU_COMMON_H
