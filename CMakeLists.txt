cmake_minimum_required(VERSION 3.5)
project(CPacketSniffer)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
set(WpdPath C:/WpdPack)

include_directories(${WpdPath}/Include)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")

set(SOURCE_FILES main.c nr_packet_interface.c nr_packet_interface.h nr_network_processes.c nr_network_processes.h nr_strop.c nr_strop.h)
add_executable(CPacketSniffer ${SOURCE_FILES})

target_link_libraries(CPacketSniffer ${WpdPath}/Lib/wpcap.lib)