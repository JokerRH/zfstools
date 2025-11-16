cmake_minimum_required( VERSION 3.10 )
project( zfstools C )

include( GNUInstallDirs )
include( CMakePackageConfigHelpers )
include( CMakeDependentOption )

option( WITH_LOADKEY "Build the loadkey library" ON )
cmake_dependent_option( WITH_ZFSTOOLS "Build the zfstools library" ON  "NOT WIN32" OFF )
cmake_dependent_option( WITH_KEYSETUP "Build the keysetup tool" ON "WITH_LOADKEY" OFF )
cmake_dependent_option( WITH_WRITEKEY "Build the writekey tool" ON "WITH_LOADKEY" OFF )
cmake_dependent_option( WITH_ZFSMOUNT "Build the zfsmount tool" ON "WITH_LOADKEY AND WITH_ZFSTOOLS AND NOT WIN32" OFF )

if( DEFINED PEM )
	# Convert PEM string into a C array initializer
	string( LENGTH "${PEM}" PEM_LEN )

	set( PEM_BYTES "" )
	math( EXPR MAX_INDEX "${PEM_LEN}-2" )
	foreach( I RANGE 0 ${MAX_INDEX} 2 )
		string( SUBSTRING "${PEM}" ${I} 2 HEXPAIR )
		set( PEM_BYTES "${PEM_BYTES}0x${HEXPAIR}, " )
	endforeach( )

	# Remove trailing comma+space
	string( REGEX REPLACE ", $" "" PEM_BYTES "${PEM_BYTES}" )
endif( )

if( DEFINED KEY_WRAPPED )
	# Convert KEY_WRAPPED string into a C array initializer
	string( LENGTH "${KEY_WRAPPED}" KEY_WRAPPED_LEN )

	set( KEY_WRAPPED_BYTES "" )
	math( EXPR MAX_INDEX "${KEY_WRAPPED_LEN}-2" )
	foreach( I RANGE 0 ${MAX_INDEX} 2 )
		string( SUBSTRING "${KEY_WRAPPED}" ${I} 2 HEXPAIR )
		set( KEY_WRAPPED_BYTES "${KEY_WRAPPED_BYTES}0x${HEXPAIR}, " )
	endforeach( )

	# Remove trailing comma+space
	string( REGEX REPLACE ", $" "" KEY_WRAPPED_BYTES "${KEY_WRAPPED_BYTES}" )
endif( )

if( DEFINED POOL_VDEVS )
	# Convert ":" -> "\0"
	set( VDEV_STRING "${POOL_VDEVS}" )
	string( REPLACE ":" "\\0" VDEV_STRING "${VDEV_STRING}" )
	# Add the final NULL terminator
	set( VDEV_STRING "${VDEV_STRING}\\0" )
endif( )

if( WITH_LOADKEY )
	add_subdirectory( loadkey )
endif( )
if( WITH_ZFSTOOLS )
	add_subdirectory( zfstools )
endif( )
if( WITH_KEYSETUP )
	add_subdirectory( keysetup )
endif( )
if( WITH_WRITEKEY )
	add_subdirectory( writekey )
endif( )
if( WITH_ZFSMOUNT )
	add_subdirectory( zfsmount )
endif( )