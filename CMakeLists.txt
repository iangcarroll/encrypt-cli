cmake_minimum_required(VERSION 2.8.9)
project (encrypt-cli)

include(Findsodium.cmake)

link_directories(sodium_LIBRARY_RELEASE)
include_directories(sodium_INCLUDE_DIR)

add_executable(encrypt-cli main.cpp)
target_link_libraries(encrypt-cli sodium)