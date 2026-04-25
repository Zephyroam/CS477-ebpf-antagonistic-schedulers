
file(GLOB SOURCES
    "*.cc"
    "*.h"
)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0")

add_definitions(-D_GNU_SOURCE)

add_executable(shinjuku ${SOURCES})

target_include_directories(shinjuku PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/
    ${CMAKE_CURRENT_SOURCE_DIR}/../
    ${CMAKE_CURRENT_SOURCE_DIR}/../utils
)

if (GFLAGS_USE_TARGET_NAMESPACE)
  if (TARGET gflags::gflags)
    target_link_libraries(shinjuku gflags::gflags rocksdb dl)
  else ()
    message(FATAL_ERROR "gflags::gflags target not defined")
  endif ()
else ()
  if (TARGET gflags)
    target_link_libraries(shinjuku gflags rocksdb dl)
  else ()
    message(FATAL_ERROR "gflags target not defined")
  endif ()
endif ()
