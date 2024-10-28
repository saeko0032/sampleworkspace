cmake_minimum_required(VERSION 3.10)

project(sampleworkspace)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_GENERATOR_PLATFORM x64)
set(CMAKE_TOOLCHAIN_FILE ${CMAKE_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake)

add_executable(sampleworkspace main.cpp rsa_encryption.cpp key_storage.cpp)

target_link_libraries(sampleworkspace Crypt32 Bcrypt)
