cmake_minimum_required(VERSION 3.16)
project(PiPwChecker CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Release)

find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(pw_checker
  src/main.cpp
  src/analyzer.cpp
  src/breach.cpp
)

target_include_directories(pw_checker PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(pw_checker PRIVATE CURL::libcurl OpenSSL::SSL OpenSSL::Crypto)
