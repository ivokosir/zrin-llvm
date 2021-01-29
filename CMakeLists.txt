cmake_minimum_required(VERSION 3.19)
project(zrin VERSION 0.1)

set(CMAKE_CXX_STANDARD 20)

find_package(LLVM REQUIRED CONFIG)
add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})

add_executable(${CMAKE_PROJECT_NAME})
add_subdirectory(src)

llvm_map_components_to_libnames(llvm_libs
  core
  AllTargetsCodeGens
)
target_link_libraries(${CMAKE_PROJECT_NAME} ${llvm_libs})
