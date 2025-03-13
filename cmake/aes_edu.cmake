# AES EDUCATIONAL IMPLEMENTATION
set(AESEDU_DIR ${CMAKE_SOURCE_DIR}/aes-educational)
FILE(GLOB_RECURSE AESEDU_SOURCES ${AESEDU_DIR}/src/*.cpp)

add_executable(aes_edu ${AESEDU_SOURCES})
target_include_directories(aes_edu PRIVATE ${AESEDU_DIR}/include/)
if (CMAKE_DEBUG_KEY_EXPANSION)
    target_compile_definitions(aes_edu PRIVATE DEBUG_FIPS_197_APPENDIX_A=1)
endif ()

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    if(MEM_SANITIZER)
        target_use_mem_sanitizer(aes_edu enable)
    endif()
endif()
