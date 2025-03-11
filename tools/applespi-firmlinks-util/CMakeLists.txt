add_executable(applespi-firmlinks-util applespi-firmlinks-util.c)
target_link_libraries(applespi-firmlinks-util PRIVATE applespi-c-header "$<LINK_LIBRARY:FRAMEWORK,CoreFoundation>" "$<LINK_LIBRARY:FRAMEWORK,${CMAKE_CURRENT_SOURCE_DIR}/../../tbd/frameworks/APFS>")
