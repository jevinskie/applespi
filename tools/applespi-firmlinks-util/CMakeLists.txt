add_executable(applespi-firmlinks-util applespi-firmlinks-util.c)
target_link_libraries(applespi-firmlinks-util PRIVATE applespi-c-header "-framework CoreFoundation")
