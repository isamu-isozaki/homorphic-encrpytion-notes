# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.24

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/Cellar/cmake/3.24.3/bin/cmake

# The command to remove a file.
RM = /usr/local/Cellar/cmake/3.24.3/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/jparlett/Documents/helib/homorphic-encrpytion-notes/helib_basics

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/jparlett/Documents/helib/homorphic-encrpytion-notes/helib_basics/build

# Include any dependencies generated for this target.
include CMakeFiles/ckks_demo.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/ckks_demo.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/ckks_demo.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/ckks_demo.dir/flags.make

CMakeFiles/ckks_demo.dir/ckks_demo.cpp.o: CMakeFiles/ckks_demo.dir/flags.make
CMakeFiles/ckks_demo.dir/ckks_demo.cpp.o: /Users/jparlett/Documents/helib/homorphic-encrpytion-notes/helib_basics/ckks_demo.cpp
CMakeFiles/ckks_demo.dir/ckks_demo.cpp.o: CMakeFiles/ckks_demo.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/jparlett/Documents/helib/homorphic-encrpytion-notes/helib_basics/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/ckks_demo.dir/ckks_demo.cpp.o"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/ckks_demo.dir/ckks_demo.cpp.o -MF CMakeFiles/ckks_demo.dir/ckks_demo.cpp.o.d -o CMakeFiles/ckks_demo.dir/ckks_demo.cpp.o -c /Users/jparlett/Documents/helib/homorphic-encrpytion-notes/helib_basics/ckks_demo.cpp

CMakeFiles/ckks_demo.dir/ckks_demo.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/ckks_demo.dir/ckks_demo.cpp.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/jparlett/Documents/helib/homorphic-encrpytion-notes/helib_basics/ckks_demo.cpp > CMakeFiles/ckks_demo.dir/ckks_demo.cpp.i

CMakeFiles/ckks_demo.dir/ckks_demo.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/ckks_demo.dir/ckks_demo.cpp.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/jparlett/Documents/helib/homorphic-encrpytion-notes/helib_basics/ckks_demo.cpp -o CMakeFiles/ckks_demo.dir/ckks_demo.cpp.s

# Object files for target ckks_demo
ckks_demo_OBJECTS = \
"CMakeFiles/ckks_demo.dir/ckks_demo.cpp.o"

# External object files for target ckks_demo
ckks_demo_EXTERNAL_OBJECTS =

ckks_demo: CMakeFiles/ckks_demo.dir/ckks_demo.cpp.o
ckks_demo: CMakeFiles/ckks_demo.dir/build.make
ckks_demo: /usr/local/helib_pack/lib/libhelib.a
ckks_demo: /usr/local/helib_pack/lib/libntl.dylib
ckks_demo: /usr/local/helib_pack/lib/libgmp.dylib
ckks_demo: CMakeFiles/ckks_demo.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/jparlett/Documents/helib/homorphic-encrpytion-notes/helib_basics/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable ckks_demo"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/ckks_demo.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/ckks_demo.dir/build: ckks_demo
.PHONY : CMakeFiles/ckks_demo.dir/build

CMakeFiles/ckks_demo.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/ckks_demo.dir/cmake_clean.cmake
.PHONY : CMakeFiles/ckks_demo.dir/clean

CMakeFiles/ckks_demo.dir/depend:
	cd /Users/jparlett/Documents/helib/homorphic-encrpytion-notes/helib_basics/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/jparlett/Documents/helib/homorphic-encrpytion-notes/helib_basics /Users/jparlett/Documents/helib/homorphic-encrpytion-notes/helib_basics /Users/jparlett/Documents/helib/homorphic-encrpytion-notes/helib_basics/build /Users/jparlett/Documents/helib/homorphic-encrpytion-notes/helib_basics/build /Users/jparlett/Documents/helib/homorphic-encrpytion-notes/helib_basics/build/CMakeFiles/ckks_demo.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/ckks_demo.dir/depend
