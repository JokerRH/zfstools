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

install( TARGETS zfstools
	EXPORT zfstoolsTargets
	RUNTIME DESTINATION bin COMPONENT ${CMAKE_INSTALL_LIBDIR}
	LIBRARY DESTINATION lib COMPONENT ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION lib COMPONENT ${CMAKE_INSTALL_BINDIR}
	FILE_SET public_headers DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/zfstools
)

#
# Packaging
#
install( EXPORT zfstoolsTargets
	FILE zfstoolsTargets.cmake
	NAMESPACE zfstools::
	DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/zfstools
)

configure_package_config_file( "${CMAKE_CURRENT_SOURCE_DIR}/Config.cmake.in"
	"${CMAKE_CURRENT_BINARY_DIR}/zfstoolsConfig.cmake"
	INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/zfstools
)

write_basic_package_version_file(
	${CMAKE_CURRENT_BINARY_DIR}/zfstoolsConfigVersion.cmake
	VERSION 0.1.0
	COMPATIBILITY SameMajorVersion
)

# Install Config and ConfigVersion files
install(
	FILES
		"${CMAKE_CURRENT_BINARY_DIR}/zfstoolsConfig.cmake"
		"${CMAKE_CURRENT_BINARY_DIR}/zfstoolsConfigVersion.cmake"
	DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/zfstools"
)