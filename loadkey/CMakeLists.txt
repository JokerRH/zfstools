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

target_sources(loadkey
	PUBLIC
		FILE_SET public_headers
		TYPE HEADERS
		BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/..
		FILES
			loadkey.h
	PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/loadkey.c
		${CMAKE_CURRENT_SOURCE_DIR}/unwrap.c

		$<$<PLATFORM_ID:Windows>:${CMAKE_CURRENT_SOURCE_DIR}/pcscd_win32.c>
		$<$<PLATFORM_ID:Windows>:${CMAKE_CURRENT_SOURCE_DIR}/readpin_win32.c>
		$<$<PLATFORM_ID:Windows>:${CMAKE_CURRENT_SOURCE_DIR}/makedev_win32.c>

		$<$<NOT:$<PLATFORM_ID:Windows>>:${CMAKE_CURRENT_SOURCE_DIR}/pcscd.c>
		$<$<NOT:$<PLATFORM_ID:Windows>>:${CMAKE_CURRENT_SOURCE_DIR}/readpin.c>
		$<$<NOT:$<PLATFORM_ID:Windows>>:${CMAKE_CURRENT_SOURCE_DIR}/makedev.c>
)

target_include_directories( loadkey PRIVATE ${CMAKE_SOURCE_DIR}/shared )
target_link_libraries( loadkey PRIVATE PkgConfig::YKCS11 )

if( DEFINED DEBUG_KEY )
	target_compile_definitions( loadkey PRIVATE "DEBUG_KEY={${DEBUG_KEY_BYTES}}" )
endif()

install( TARGETS loadkey
	EXPORT ${ZFSTOOLS_EXPORT_SET}
	RUNTIME DESTINATION bin
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib
	FILE_SET public_headers DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/loadkey"
)