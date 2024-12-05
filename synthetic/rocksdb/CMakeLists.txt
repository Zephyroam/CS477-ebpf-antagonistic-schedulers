cmake_minimum_required(VERSION 3.21)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O3")

set(CMAKE_CXX_STANDARD 20)

# set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_definitions(-D_GNU_SOURCE)

project(MyProject)

find_package(gflags REQUIRED)

add_subdirectory(external/rocksdb)


# target_include_directories(rocksdb PRIVATE ${GFLAGS_INCLUDE_DIR})
# target_link_libraries(rocksdb PRIVATE gflags)

add_subdirectory(src)



# add_executable(shinjuku shinjuku.cc)

# target_link_libraries(shinjuku PRIVATE gflags)
# target_link_libraries(shinjuku rocksdb dl)