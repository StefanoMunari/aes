AES - Advanced Encryption Standard
----------------------------------

Implementations of AES from FIPS-197

Specification: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf

Step-by-step dissection of algorithm with reported values for each accepted key length: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core_All.pdf

AES Educational
---------------

Educational purpose oriented implementation in C++

Reference: aes-educational/

Easy to follow/study specification

Enable debug prints which matches the Appendix of the specification or AES_Core_All.pdf format via Cmake variables:
```
-DCMAKE_DEBUG_KEY_EXPANSION=1 -DCMAKE_DEBUG_CIPHER=1
```
LICENSE
-------
GPL-v3: free to use, modify, and distribute, derivative works must be licensed under GPLv3.