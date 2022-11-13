# Runs this from the build dir, make sure your executables are defined in the CMakeLists.txt file

# path to installed helib cmake files this prefix [/usr/local/helib_pack] will be different on your system
helib_dir="/usr/local/helib_pack/share/cmake/helib/"

# -S source dir, -B dest dir
cmake -Dhelib_DIR=$helib_dir -S .. -B . -Wno-dev

# make the target excutables
make