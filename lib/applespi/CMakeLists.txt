add_library(applespi-c applespi-dummy.c)
target_include_directories(applespi-c INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/../../include)

add_library(applespi-c-header INTERFACE)
target_include_directories(applespi-c-header INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/../../include)
