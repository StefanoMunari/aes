#include <cstdint>
#include <array>
#include <string>
#include "key_expansion.h"
#include "cipher.h"
#include "version.h"

using namespace aes_edu;

static
int help(std::string prog_name)
{
    std::cout << "Usage: " << prog_name <<" [options]\n";
    std::cout << "Options:\n";
    std::cout << "  -h, --help  Show this help message and exit\n";
    return 0;
}

int main(int argc, char* argv[]) {
    std::cout << "VERSION:" << version << std::endl;
    if (argc > 1 && (std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help"))
        return help(std::string(argv[0]));
    // Appendix A.1: Expansion of a 128-bit Key
    {
        std::cout << "[Expansion of a 128-bit Key]\n";
        static constexpr auto key_size = 16U;
        std::array<uint8_t, key_size> key{
            0x2b, 0x7e, 0x15, 0x16,
            0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
        };
        auto expanded_key = key_expansion::expand<key_size>(key);
        const auto plaintext_size = 16U;
        uint8_t plaintext[] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
        std::cout << "[Cipher with 128-bit Key]\n";
        auto ciphertext = cipher::cipher<key_size>(plaintext, plaintext_size, expanded_key);
        std::cout << "O  ";
        utils::print_hex(ciphertext);
        std::cout << "\n";
    }
    // Appendix A.2: Expansion of a 192-bit Key
    {
        std::cout << "[Expansion of a 192-bit Key]\n";
        static constexpr auto key_size = 24U;
        std::array<uint8_t, key_size> key{
            0x8e, 0x73, 0xb0, 0xf7,
            0xda, 0x0e, 0x64, 0x52,
            0xc8, 0x10, 0xf3, 0x2b,
            0x80, 0x90, 0x79, 0xe5,
            0x62, 0xf8, 0xea, 0xd2,
            0x52, 0x2c, 0x6b, 0x7b
        };
        key_expansion::expand<key_size>(key);
    }
    // Appendix A.3: Expansion of a 256-bit Key
    {
        std::cout << "[Expansion of a 256-bit Key]\n";
        static constexpr auto key_size = 32U;
        std::array<uint8_t, key_size> key{
            0x60, 0x3d, 0xeb, 0x10,
            0x15, 0xca, 0x71, 0xbe,
            0x2b, 0x73, 0xae, 0xf0,
            0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x2c, 0x07,
            0x3b, 0x61, 0x08, 0xd7,
            0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4
        };
        key_expansion::expand<key_size>(key);
    }
    return 0;
}
