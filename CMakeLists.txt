cmake_minimum_required(VERSION 3.10)

project(gst-corrupter VERSION 0.1.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find required packages
find_package(PkgConfig REQUIRED)

# Find GStreamer dependencies
pkg_check_modules(GSTREAMER REQUIRED gstreamer-1.0>=1.18)
pkg_check_modules(GSTREAMER_BASE REQUIRED gstreamer-base-1.0>=1.18)

# Add subdirectory
add_subdirectory(src)
