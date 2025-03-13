#ifndef AESEDU_UTILS_H
#define AESEDU_UTILS_H

#include <cstdint>
#include <cstring>
#include <array>
#include <iostream>
#include <iomanip>

namespace aes_edu::utils {

    template<std::size_t SIZE>
    void print_hex(const std::array<uint8_t, SIZE>& arr) {

        for (size_t i = 0; i < arr.size(); ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(arr[i]);
        }
        std::cout << " " << std::dec;
    }

}

#endif //AESEDU_UTILS_H
