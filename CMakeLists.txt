cmake_minimum_required(VERSION 3.10)

project(sampleworkspace)

set(CMAKE_CXX_STANDARD 17)

add_executable(sampleworkspace main.cpp rsa_encryption.cpp key_storage.cpp)

target_link_libraries(sampleworkspace Crypt32 Bcrypt)
