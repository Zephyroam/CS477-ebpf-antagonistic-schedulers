cmake_minimum_required(VERSION 3.10)

project(MyProject)

add_subdirectory(external/gflags)
add_subdirectory(external/rocksdb)

add_subdirectory(src)



# add_executable(shinjuku shinjuku.cc)

# target_link_libraries(shinjuku PRIVATE gflags)
# target_link_libraries(shinjuku rocksdb dl)