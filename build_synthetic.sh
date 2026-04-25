#!/bin/sh

cd ./synthetic
# create build directory if it doesn't exist
mkdir -p build
cd build

# use cmake to generate build files
cmake ..

# build the project
make