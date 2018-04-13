cmake_minimum_required(VERSION 3.0)
project(socks-proxy VERSION 0.1.0 LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

include(cmake/compiler-options.cmake)
include(cmake/FindGLog.cmake)

add_subdirectory(deps/googletest EXCLUDE_FROM_ALL)

find_package(Boost COMPONENTS system REQUIRED)
find_package(GLog REQUIRED)
find_package(Threads REQUIRED)

include_directories(${GLOG_INCLUDE_DIR})
include_directories(deps/googletest/googlemock/include)
include_directories(deps/googletest/googletest/include)
include_directories(src)

set(SRCS src/socks4.cc)
set(TEST_SRCS src/test_socks4.cc)

add_library(socks-obj OBJECT ${SRCS})

add_executable(socks-proxy src/main.cc $<TARGET_OBJECTS:socks-obj>)
target_link_libraries(socks-proxy Boost::system
                                  glog
                                  Threads::Threads)

add_executable(socks-proxy-test ${TEST_SRCS} $<TARGET_OBJECTS:socks-obj>)
target_link_libraries(socks-proxy-test Boost::system
                                       glog
                                       gtest gtest_main
                                       Threads::Threads)

enable_testing()
add_test(NAME test-all
         COMMAND ./socks-proxy-test)
