cmake_minimum_required(VERSION 3.21)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
add_compile_definitions(_POSIX_C_SOURCE=200809L)


project(MyProject)

find_package(gflags REQUIRED)

add_subdirectory(external/rocksdb)


# target_include_directories(rocksdb PRIVATE ${GFLAGS_INCLUDE_DIR})
# target_link_libraries(rocksdb PRIVATE gflags)

add_subdirectory(src)



# add_executable(shinjuku shinjuku.cc)

# target_link_libraries(shinjuku PRIVATE gflags)
# target_link_libraries(shinjuku rocksdb dl)