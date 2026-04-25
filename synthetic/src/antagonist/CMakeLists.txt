
file(GLOB SOURCES
    "*.cc"
    "*.h"
)

add_executable(antagonist ${SOURCES})

target_include_directories(antagonist PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../
    ${CMAKE_CURRENT_SOURCE_DIR}/../utils
)

if (GFLAGS_USE_TARGET_NAMESPACE)
  if (TARGET gflags::gflags)
    target_link_libraries(antagonist gflags::gflags)
  else ()
    message(FATAL_ERROR "gflags::gflags target not defined")
  endif ()
else ()
  if (TARGET gflags)
    target_link_libraries(antagonist gflags)
  else ()
    message(FATAL_ERROR "gflags target not defined")
  endif ()
endif ()
