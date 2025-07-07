cmake_minimum_required(VERSION 3.10.0)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /MANIFEST:NO") # MANIFEST:NO yea
#set(LIBRARY_OUTPUT_PATH "C:\\Users\\LatterRarity70\\Desktop\\idk test") # dll output
cmake_policy(SET CMP0057 NEW)

project ("user95401.signature-scan-patcher")

#mod
file(GLOB_RECURSE SRC "src/*")
add_library(${PROJECT_NAME} SHARED ${SRC})
include_directories("src/")
