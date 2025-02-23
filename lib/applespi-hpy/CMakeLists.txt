find_package(Python3 COMPONENTS Interpreter Development)

execute_process(
    COMMAND ${Python3_EXECUTABLE} -c "import hpy.devel; print(';'.join(hpy.devel.HPyDevel().get_extra_include_dirs()))"
    OUTPUT_VARIABLE HPY_INCLUDE_DIRS
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
execute_process(
    COMMAND ${Python3_EXECUTABLE} -c "import hpy.devel; print(';'.join(hpy.devel.HPyDevel().get_ctx_sources()))"
    OUTPUT_VARIABLE HPY_CTX_SOURCES
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

add_library(applespi-hpy SHARED applespi-hpy.c ${HPY_CTX_SOURCES})

target_compile_definitions(applespi-hpy PRIVATE HPY_ABI_CPYTHON)
target_include_directories(applespi-hpy PRIVATE ${Python3_INCLUDE_DIRS} ${HPY_INCLUDE_DIRS})
target_link_libraries(applespi-hpy PRIVATE ${Python3_LIBRARIES} applespi-c)
set_target_properties(applespi-hpy PROPERTIES PREFIX "")
set_target_properties(applespi-hpy PROPERTIES OUTPUT_NAME "ffi")
set_target_properties(applespi-hpy PROPERTIES SUFFIX ".${Python3_SOABI}${CMAKE_SHARED_MODULE_SUFFIX}")
