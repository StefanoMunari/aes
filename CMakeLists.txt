cmake_minimum_required(VERSION 3.30)
project(aes)
# configuration
set(CMAKE_CXX_STANDARD 20)
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_CXX_CLANG_TIDY clang-tidy -format-style=file)
endif()
# tools
include(cmake/sanitizer.cmake)
# targets
include(cmake/aes_edu.cmake)