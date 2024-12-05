cmake_minimum_required(VERSION 3.21)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

project(MyProject)

find_package(gflags REQUIRED)

add_subdirectory(external/rocksdb)

add_subdirectory(src/rocksdb)
add_subdirectory(src/antagonist)
