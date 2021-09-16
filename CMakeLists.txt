cmake_minimum_required(VERSION 2.9)
project(bag_rdr)

if (BAG_RDR_NO_ROS)
  set (LOCAL_EXTRA_DEPENDS lz4)
  add_compile_definitions (BAG_RDR_NO_ROS)
  add_compile_definitions (BAG_RDR_USE_SYSTEM_LZ4)
  find_package (PkgConfig REQUIRED)
  pkg_check_modules(LOCAL_PKG_CONFIG REQUIRED liblz4)
else ()
  set (LOCAL_CATKIN_DEPENDS roslz4)
  set (LOCAL_CATKIN_REQUIRES roscpp roslz4)
  find_package(catkin REQUIRED ${LOCAL_CATKIN_REQUIRES})
  catkin_package(INCLUDE_DIRS . ${LIBCOMMON_INCLUDE_PATH}
                 LIBRARIES bag_rdr
                 CATKIN_DEPENDS ${LOCAL_CATKIN_DEPENDS})
endif ()


set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(LIBCOMMON_INCLUDE_PATH deps/common_cxx)

include_directories(. ${catkin_INCLUDE_DIRS} ${LIBCOMMON_INCLUDE_PATH} ${LOCAL_PKG_CONFIG_INCLUDE_DIRS})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -W -Wno-maybe-uninitialized")

add_library(bag_rdr STATIC bag_rdr.cpp)
target_link_libraries(bag_rdr ${catkin_LIBRARIES} bz2 ${LOCAL_PKG_CONFIG_LIBRARIES})

add_executable(extract_timestamps extract_timestamps.cpp)
target_link_libraries(extract_timestamps bag_rdr)

add_executable(bag_topic_sizes topic_sizes.cpp)
target_link_libraries(bag_topic_sizes bag_rdr)

install(TARGETS extract_timestamps
        ARCHIVE DESTINATION ${CATKIN_PACKAGE_LIB_DESTINATION}
        LIBRARY DESTINATION ${CATKIN_PACKAGE_LIB_DESTINATION}
        RUNTIME DESTINATION ${CATKIN_PACKAGE_BIN_DESTINATION}
)

