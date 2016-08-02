cmake_minimum_required(VERSION 3.5)
project(CPacketSniffer)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
set(WpdPath C:/WpdPack)

include_directories(${WpdPath}/Include)

set(SOURCE_FILES main.c nr_packet_interface.c nr_packet_interface.h nr_network_processes.c nr_network_processes.h nr_strop.c nr_strop.h)
add_executable(CPacketSniffer ${SOURCE_FILES})

target_link_libraries(CPacketSniffer ${WpdPath}/Lib/wpcap.lib)