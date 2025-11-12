cmake_minimum_required( VERSION 3.10 )
project( zfstools C )

include( GNUInstallDirs )
include( CMakePackageConfigHelpers )

add_subdirectory( loadkey )
add_subdirectory( zfstools )
add_subdirectory( writekey )
add_subdirectory( zfsmount )