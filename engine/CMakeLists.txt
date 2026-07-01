cmake_minimum_required(VERSION 3.16)
project(netsentinel VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_library(PCAP_LIBRARY pcap REQUIRED)
find_path(PCAP_INCLUDE_DIR pcap.h REQUIRED)
find_package(Threads REQUIRED)

set(SOURCES
    src/main.cpp
    src/capture.cpp
    src/dissector.cpp
    src/profiler.cpp
)

add_executable(netsentinel ${SOURCES})
target_include_directories(netsentinel PRIVATE include/ ${PCAP_INCLUDE_DIR})
target_link_libraries(netsentinel PRIVATE ${PCAP_LIBRARY} Threads::Threads)
target_compile_options(netsentinel PRIVATE -Wall -Wextra -O2)
