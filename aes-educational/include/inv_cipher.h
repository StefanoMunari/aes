#ifndef AES_EDU_INV_CIPHER_H
#define AES_EDU_INV_CIPHER_H

#include <array>
#include <cstdint>
#include "utils.h"

namespace aes_edu::inv_cipher {

    std::array<uint8_t, utils::STATE_SIZE> inv_cipher_128(std::array<uint8_t, utils::STATE_SIZE> plaintext,
                                                      std::array<uint8_t, utils::EXPANDED_KEY_SIZE(16U)> ex_key);

    std::array<uint8_t, utils::STATE_SIZE> inv_cipher_192(std::array<uint8_t, utils::STATE_SIZE> plaintext,
                                                      std::array<uint8_t, utils::EXPANDED_KEY_SIZE(24U)> ex_key);

    std::array<uint8_t, utils::STATE_SIZE> inv_cipher_256(std::array<uint8_t, utils::STATE_SIZE> plaintext,
                                                      std::array<uint8_t, utils::EXPANDED_KEY_SIZE(32U)> ex_key);

    template <std::size_t KEY_SIZE>
    std::array<uint8_t, utils::STATE_SIZE>
    inv_cipher(std::array<uint8_t, utils::STATE_SIZE> plaintext,
           std::array<uint8_t, utils::EXPANDED_KEY_SIZE(KEY_SIZE)> ex_key) {
        if constexpr (KEY_SIZE == 16U)
        {
            return inv_cipher_128(plaintext, ex_key);
        }
        else if constexpr (KEY_SIZE == 24U)
        {
            return inv_cipher_192(plaintext, ex_key);
        }
        else if constexpr (KEY_SIZE == 32U)
        {
            return inv_cipher_256(plaintext, ex_key);
        }
        else
        {
            throw std::invalid_argument("Invalid KEY_SIZE");
        }
    }

} // inv_cipher

#endif //AES_EDU_INV_CIPHER_H
