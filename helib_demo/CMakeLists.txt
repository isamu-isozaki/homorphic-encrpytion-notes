cmake_minimum_required(VERSION 3.10.2 FATAL_ERROR)

## Use -std=c++17 as default.
set(CMAKE_CXX_STANDARD 17)
## Disable C++ extensions
set(CMAKE_CXX_EXTENSIONS OFF)
## Require full C++ standard
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# must specify -Dhelib_DIR=<helib install prefix>/share/cmake/helib when calling cmake
find_package(helib)

# add_subdirectory(tutorial)
# add_executable(01_ckks_basics 01_ckks_basics.cpp)
# add_executable(ckks_sample ckks_sample.cpp)
add_executable(ckks_demo ckks_demo.cpp)
# target_link_libraries(ckks_sample helib)
target_link_libraries(ckks_demo helib)
