#include <cstdint>
#include <array>
#include <inv_cipher.h>
#include <string>
#include <cstring>
#include "key_expansion.h"
#include "cipher.h"
#include "version.h"

using namespace aes_edu;
using namespace aes_edu::constants;

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
    {// Appendix A.1: Expansion of a 128-bit Key
        std::cout << "[Expansion of a 128-bit Key]\n";
        static constexpr auto key_size = 16U;
        std::array<uint8_t, key_size> key{
            0x2b, 0x7e, 0x15, 0x16,
            0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
        };
        auto expanded_key = key_expansion::expand<key_size>(key);
    // Appendix B: Cipher Example (using 128-bit key, 128-bit plaintext)
        std::array<uint8_t, key_size> plaintext {
            0x32, 0x43, 0xf6, 0xa8,
            0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2,
            0xe0, 0x37, 0x07, 0x34
        };
        std::cout << "[Cipher with 128-bit Key]\n";
        auto ciphertext = cipher::cipher<key_size>(plaintext, expanded_key);
        std::cout << "O  ";
        utils::print_hex(ciphertext);
        std::cout << "\n";
        std::cout << "[Decryption with 128-bit Key]\n";
        auto deciphered_text = inv_cipher::inv_cipher<key_size>(ciphertext, expanded_key);
        std::cout << ((plaintext == deciphered_text) ? "SUCCESS" : "FAILED") << "\n";
    }
    {// Appendix A.2: Expansion of a 192-bit Key
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
        auto expanded_key = key_expansion::expand<key_size>(key);
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core_All.pdf
        // reference ECB-AES192 (Encryption)
        // 64B plaintext -> 4 iterations on cipher: each one generates a block of ciphertext
        static constexpr auto plaintext_size = 64U;
        std::array<uint8_t, plaintext_size> plaintext {
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
            0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
            0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
        };
        std::cout << "[Cipher with 192-bit Key]\n";
        std::array<uint8_t, STATE_SIZE> ciphertext_sample;
        for (auto i = 0; i < plaintext_size; i += STATE_SIZE) {
            auto state = utils::sub_array<STATE_SIZE>(plaintext, i);
            auto ciphertext = cipher::cipher<key_size>(state, expanded_key);
            std::cout << "O  ";
            utils::print_hex(ciphertext);
            std::cout << "\n";
            ciphertext_sample = ciphertext;
        }
        std::cout << "[Decryption with 192-bit Key]\n";
        auto deciphered_text = inv_cipher::inv_cipher<key_size>(ciphertext_sample, expanded_key);
        std::array<uint8_t, STATE_SIZE> plaintext_sample;
        memcpy(plaintext_sample.data(), &plaintext[plaintext_size-STATE_SIZE], STATE_SIZE);
        std::cout << ((plaintext_sample == deciphered_text) ? "SUCCESS" : "FAILED") << "\n";
    }
    {// Appendix A.3: Expansion of a 256-bit Key
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
        auto expanded_key = key_expansion::expand<key_size>(key);
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core_All.pdf
        // reference ECB-AES256 (Encryption)
        // 64B plaintext -> 4 iterations on cipher: each one generates a block of ciphertext
        static constexpr auto plaintext_size = 64U;
        std::array<uint8_t, plaintext_size> plaintext {
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
            0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
            0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
        };
        std::cout << "[Cipher with 256-bit Key]\n";
        std::array<uint8_t, STATE_SIZE> ciphertext_sample;
        for (auto i = 0; i < plaintext_size; i += STATE_SIZE) {
            auto state = utils::sub_array<STATE_SIZE>(plaintext, i);
            auto ciphertext = cipher::cipher<key_size>(state, expanded_key);
            std::cout << "O  ";
            utils::print_hex(ciphertext);
            std::cout << "\n";
        }
        std::cout << "[Decryption with 256-bit Key]\n";
        auto deciphered_text = inv_cipher::inv_cipher<key_size>(ciphertext_sample, expanded_key);
        std::array<uint8_t, STATE_SIZE> plaintext_sample;
        memcpy(plaintext_sample.data(), &plaintext[plaintext_size-STATE_SIZE], STATE_SIZE);
        std::cout << ((plaintext_sample == deciphered_text) ? "SUCCESS" : "FAILED") << "\n";
    }
    return 0;
}
