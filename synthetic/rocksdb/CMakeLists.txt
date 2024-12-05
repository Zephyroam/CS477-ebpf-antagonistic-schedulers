cmake_minimum_required(VERSION 3.10)

project(MyProject)

set(GFLAGS_INCLUDE_DIR ${CMAKE_BINARY_DIR}/external/gflags/include)
set(GFLAGS_LIBRARY_DIR ${CMAKE_BINARY_DIR}/external/gflags/lib)

add_subdirectory(external/gflags)
add_subdirectory(external/rocksdb)


target_include_directories(rocksdb PRIVATE ${GFLAGS_INCLUDE_DIR})
target_link_libraries(rocksdb PRIVATE gflags)

add_subdirectory(src)



# add_executable(shinjuku shinjuku.cc)

# target_link_libraries(shinjuku PRIVATE gflags)
# target_link_libraries(shinjuku rocksdb dl)