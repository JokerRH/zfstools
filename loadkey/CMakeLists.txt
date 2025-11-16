#
# Process inputs
#
if( DEFINED DEBUG_KEY )
	# Convert DEBUG_KEY string into a C array initializer
	string( LENGTH "${DEBUG_KEY}" DEBUG_KEY_LEN )
	if( NOT DEBUG_KEY_LEN EQUAL 64 )
		message( FATAL_ERROR "DEBUG_KEY must be 256 bit" )
	endif( )

	set( DEBUG_KEY_BYTES "" )
	math( EXPR MAX_INDEX "${DEBUG_KEY_LEN}-2" )
	foreach( I RANGE 0 ${MAX_INDEX} 2 )
		string( SUBSTRING "${DEBUG_KEY}" ${I} 2 HEXPAIR )
		set( DEBUG_KEY_BYTES "${DEBUG_KEY_BYTES}0x${HEXPAIR}, " )
	endforeach( )

	# Remove trailing comma+space
	string( REGEX REPLACE ", $" "" DEBUG_KEY_BYTES "${DEBUG_KEY_BYTES}" )
endif( )

#
# loadkey library
#

add_library( loadkey STATIC )
add_library( loadkey::loadkey ALIAS loadkey )

find_package( PkgConfig REQUIRED )
pkg_check_modules( YKCS11 REQUIRED IMPORTED_TARGET ykcs11 )

target_sources( loadkey
	PUBLIC
		FILE_SET public_headers
		TYPE HEADERS
		BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/..
		FILES
			loadkey.h
	PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/loadkey.c
)

target_include_directories( loadkey PRIVATE ${CMAKE_SOURCE_DIR}/shared )
target_link_libraries( loadkey PRIVATE PkgConfig::YKCS11 )

if( DEFINED DEBUG_KEY )
	target_compile_definitions( loadkey PRIVATE "DEBUG_KEY={${DEBUG_KEY_BYTES}}" )
endif()

install( TARGETS loadkey
	EXPORT loadkeyTargets
	RUNTIME DESTINATION bin COMPONENT ${CMAKE_INSTALL_LIBDIR}
	LIBRARY DESTINATION lib COMPONENT ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION lib COMPONENT ${CMAKE_INSTALL_BINDIR}
	FILE_SET public_headers DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/loadkey
)

#
# Packaging
#
install( EXPORT loadkeyTargets
	FILE loadkeyTargets.cmake
	NAMESPACE loadkey::
	DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/loadkey
)

configure_package_config_file( "${CMAKE_CURRENT_SOURCE_DIR}/Config.cmake.in"
	"${CMAKE_CURRENT_BINARY_DIR}/loadkeyConfig.cmake"
	INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/loadkey
)

write_basic_package_version_file(
	${CMAKE_CURRENT_BINARY_DIR}/loadkeyConfigVersion.cmake
	VERSION 0.1.0
	COMPATIBILITY SameMajorVersion
)

# Install Config and ConfigVersion files
install(
	FILES
		"${CMAKE_CURRENT_BINARY_DIR}/loadkeyConfig.cmake"
		"${CMAKE_CURRENT_BINARY_DIR}/loadkeyConfigVersion.cmake"
	DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/loadkey"
)