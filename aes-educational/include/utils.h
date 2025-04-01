#ifndef AESEDU_UTILS_H
#define AESEDU_UTILS_H

#include "constants.h"
#include <cstdint>
#include <array>
#include <iostream>
#include <iomanip>
#include <algorithm>

namespace aes_edu::utils {
    namespace c = constants;

    template <std::size_t SIZE, typename T, std::size_t N>
    constexpr std::array<T, SIZE> sub_array(const std::array<T, N>& arr, const int start)
    {
        std::array<T, SIZE> result{};
        std::copy_n(arr.begin() + start, SIZE, result.begin());
        return result;
    }

    inline
    std::array<uint8_t, c::ROW_SIZE> get_row_indexes(int start)
    {
        const auto offset = c::WORD_SIZE;
        std::array<uint8_t, c::ROW_SIZE> row_indexes{};
        for (int i = 0; i < c::ROW_SIZE; ++i) row_indexes[i] = start + offset * i;
        return row_indexes;
    }


    template<std::size_t SIZE>
    void print_hex(const std::array<uint8_t, SIZE>& arr)
    {
        for (size_t i = 0; i < arr.size(); ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(arr[i]);
        }
        std::cout << " " << std::dec;
    }

}

#endif //AESEDU_UTILS_H
