add_library(applespi applespi_dummy.c)
target_include_directories(applespi INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/../../include)
