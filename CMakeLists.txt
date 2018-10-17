project(bag_rdr)

find_package(catkin REQUIRED roscpp roslz4)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(LIBCOMMON_INCLUDE_PATH deps/common_cxx)

catkin_package(INCLUDE_DIRS . ${LIBCOMMON_INCLUDE_PATH}
               LIBRARIES bag_rdr
               CATKIN_DEPENDS roslz4)

include_directories(. ${catkin_INCLUDE_DIRS} ${LIBCOMMON_INCLUDE_PATH})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -W -Wno-maybe-uninitialized")

add_library(bag_rdr STATIC bag_rdr.cpp)
target_link_libraries(bag_rdr ${catkin_LIBRARIES} bz2)

add_executable(extract_timestamps extract_timestamps.cpp)
target_link_libraries(extract_timestamps bag_rdr)

if (NOT NO_OFFLINE_TOOLS)
add_executable(bag_topic_sizes topic_sizes.cpp)
target_link_libraries(bag_topic_sizes bag_rdr)
endif (NOT NO_OFFLINE_TOOLS)

install(TARGETS extract_timestamps
        ARCHIVE DESTINATION ${CATKIN_PACKAGE_LIB_DESTINATION}
        LIBRARY DESTINATION ${CATKIN_PACKAGE_LIB_DESTINATION}
        RUNTIME DESTINATION ${CATKIN_PACKAGE_BIN_DESTINATION}
)

