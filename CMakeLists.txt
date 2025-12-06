cmake_minimum_required( VERSION 3.10 )
project( zfstools LANGUAGES C VERSION 0.1.0 )

include( GNUInstallDirs )
include( CMakePackageConfigHelpers )
include( CMakeDependentOption )

option( WITH_LOADKEY "Build the loadkey library" ON )
cmake_dependent_option( WITH_ZFSTOOLS "Build the zfstools library" ON  "NOT WIN32" OFF )
cmake_dependent_option( WITH_KEYSETUP "Build the keysetup tool" ON "WITH_LOADKEY" OFF )
cmake_dependent_option( WITH_WRITEKEY "Build the writekey tool" ON "WITH_LOADKEY" OFF )
cmake_dependent_option( WITH_ZFSMOUNT "Build the zfsmount tool" ON "WITH_LOADKEY AND WITH_ZFSTOOLS AND NOT WIN32" OFF )
option( DISABLE_ID_CHECK "Disable check for matching pool_guid" OFF )

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

if( DEFINED POOL_VDEVS )
	# Convert ":" -> "\0"
	set( VDEV_STRING "${POOL_VDEVS}" )
	string( REPLACE ":" "\\0" VDEV_STRING "${VDEV_STRING}" )
	# Add the final NULL terminator
	set( VDEV_STRING "${VDEV_STRING}\\0" )
endif( )

if( DEFINED DATASETS )
	string( REPLACE ":" ";" DATASETS "${DATASETS}" )	#Some tools (e.g. VS Code or yocto) silently escape semicolons. Allow separation using ':', too.
	set( DATASET_CALLS "" )

	list( LENGTH DATASETS LEN )

	math(EXPR REMAINDER "${LEN} % 3")
	if( NOT REMAINDER EQUAL 0 )
		message( FATAL_ERROR "DATASETS must contain a multiple of 3 entries (dataset, wrapped key, writekey path). Currently contains ${LEN} entries.")
	endif()

	math( EXPR COUNT "${LEN} / 3 - 1" )

	foreach( i RANGE 0 ${COUNT} 1 )
		math( EXPR idx0 "${i} * 3" )
		math( EXPR idx1 "${idx0} + 1" )
		math( EXPR idx2 "${idx0} + 2" )

		list( GET DATASETS ${idx0} DATASET )
		list( GET DATASETS ${idx1} KEY_WRAPPED )
		list( GET DATASETS ${idx2} PATH )

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

		string( APPEND DATASET_CALLS "DATASET( \"${DATASET}\", ( (block256_t) \{ ${KEY_WRAPPED_BYTES} \} ), \"${PATH}\" );\n" )
	endforeach( )
endif( )

#
# Prepare package
#
set( ZFSTOOLS_EXPORT_SET zfstoolsTargets )

# Export location
set( ZFSTOOLS_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/zfstools" )

# Generate package config files
configure_package_config_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/Config.cmake.in"
	"${CMAKE_CURRENT_BINARY_DIR}/zfstoolsConfig.cmake"
	INSTALL_DESTINATION ${ZFSTOOLS_INSTALL_CMAKEDIR}
)

write_basic_package_version_file(
	"${CMAKE_CURRENT_BINARY_DIR}/zfstoolsConfigVersion.cmake"
	VERSION ${PROJECT_VERSION}
	COMPATIBILITY SameMajorVersion
)

# Install config files
install(
	FILES
		"${CMAKE_CURRENT_BINARY_DIR}/zfstoolsConfig.cmake"
		"${CMAKE_CURRENT_BINARY_DIR}/zfstoolsConfigVersion.cmake"
	DESTINATION "${ZFSTOOLS_INSTALL_CMAKEDIR}"
)

# Install the global export set created by subprojects
install(
	EXPORT ${ZFSTOOLS_EXPORT_SET}
	FILE zfstoolsTargets.cmake
	NAMESPACE zfstools::
	DESTINATION "${ZFSTOOLS_INSTALL_CMAKEDIR}"
)

#
# Add libraries and executables
#
add_subdirectory( shared )
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