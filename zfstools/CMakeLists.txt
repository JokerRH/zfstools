#
# zfstools library
#

add_library( zfstools STATIC )
add_library( zfstools::zfstools ALIAS zfstools )

find_package( PkgConfig REQUIRED )
pkg_check_modules( ZFS REQUIRED IMPORTED_TARGET libzfs_core )
pkg_check_modules( BLKID REQUIRED IMPORTED_TARGET blkid )

target_sources( zfstools
	PUBLIC
		FILE_SET public_headers
		TYPE HEADERS
		BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/..
		FILES
			zfstools.h
	PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/zfstools.c
)

target_link_libraries( zfstools PUBLIC PkgConfig::ZFS PkgConfig::BLKID )
target_compile_definitions( zfstools PRIVATE _GNU_SOURCE )
if( DISABLE_ID_CHECK )
    target_compile_definitions( zfstools PRIVATE DISABLE_ID_CHECK )
endif()

install( TARGETS zfstools
	EXPORT ${ZFSTOOLS_EXPORT_SET}
	RUNTIME DESTINATION bin
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib
	FILE_SET public_headers DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/zfstools"
)