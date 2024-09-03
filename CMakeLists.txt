cmake_minimum_required(VERSION 3.10)
project(BasicIDS)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

if(MINGW)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++ -static -lpthread")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++ -static -lpthread")
endif()

# Add this line to ensure Windows doesn't define min and max macros
add_definitions(-DNOMINMAX)

# Set the Npcap SDK directory
set(NPCAP_SDK_DIR "C:/Npcap-SDK")

# Include directories
include_directories(${NPCAP_SDK_DIR}/Include)

# Link directories
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    # 64-bit
    link_directories(${NPCAP_SDK_DIR}/Lib/x64)
else()
    # 32-bit
    link_directories(${NPCAP_SDK_DIR}/Lib)
endif()

# Add the executable
add_executable(basic_ids main.cpp)

# Link libraries
target_link_libraries(basic_ids wpcap Ws2_32)

# Compiler-specific options
if(MSVC)
    # For Visual Studio
    target_compile_options(basic_ids PRIVATE /W4 /EHsc)
    # Add this to force MSVC to be more standards-compliant
    target_compile_definitions(basic_ids PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
    # For other compilers (like MinGW)
    target_compile_options(basic_ids PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Ensure the Packet.lib is also linked (required for some Npcap functions)
if(WIN32)
    target_link_libraries(basic_ids Packet)
endif()