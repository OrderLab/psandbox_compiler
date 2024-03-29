cmake_minimum_required(VERSION 3.4.3)
project(static_analyzer)

if(" ${CMAKE_SOURCE_DIR}" STREQUAL " ${CMAKE_BINARY_DIR}")
    message(FATAL_ERROR "FATAL: In-source builds are not allowed.
  You should create a build directory for building the tool.")
endif()

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -Wall -Wextra -Wno-unused-parameter -fno-rtti")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")
message(STATUS "LLVM binaries: ${LLVM_TOOLS_BINARY_DIR}")

list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${LLVM_DIR}")

set(ROOT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${ROOT_SOURCE_DIR}/cmake")

include(LLVMConfig)
include(AddLLVM)

message(STATUS "LLVM include dir: ${LLVM_INCLUDE_DIRS}")
message(STATUS "LLVM libraries dir: ${LLVM_LIBRARY_DIRS}")
message(STATUS "LLVM definitions: ${LLVM_DEFINITIONS}")

include_directories(${LLVM_INCLUDE_DIRS})
message(STATUS "Looking for headers in: ${LLVM_INCLUDE_DIRS}")
link_directories(${LLVM_LIBRARY_DIRS})
message(STATUS "Looking for libraries in: ${LLVM_LIBRARY_DIRS}")

add_definitions(${LLVM_DEFINITIONS})
if (${LLVM_PACKAGE_VERSION} VERSION_GREATER "3.4")
    llvm_map_components_to_libnames(llvm_core core)
    llvm_map_components_to_libnames(llvm_irreader irreader)
    llvm_map_components_to_libnames(llvm_bitwriter bitwriter)
    llvm_map_components_to_libnames(llvm_analysis analysis)
    llvm_map_components_to_libnames(llvm_support support)
    llvm_map_components_to_libnames(llvm_transformutils transformutils)
else()
    llvm_map_components_to_libraries(llvm_core core)
    llvm_map_components_to_libraries(llvm_irreader irreader)
    llvm_map_components_to_libraries(llvm_bitwriter bitwriter)
    llvm_map_components_to_libraries(llvm_analysis analysis)
    llvm_map_components_to_libraries(llvm_support support)
endif()

include_directories(include)
include_directories(lib)
add_subdirectory(lib)