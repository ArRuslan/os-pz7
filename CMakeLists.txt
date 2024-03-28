cmake_minimum_required(VERSION 3.28)
project(os_pz7)

set(CMAKE_CXX_STANDARD 17)
find_package(ZLIB)

add_executable(os_pz7 main.cpp)
target_link_libraries(os_pz7 ZLIB::ZLIB)