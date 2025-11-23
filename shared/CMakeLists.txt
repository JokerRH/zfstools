configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/datasets.h.in ${CMAKE_CURRENT_BINARY_DIR}/datasets.h @ONLY )

#
# shared library
#

add_library( shared INTERFACE )
target_sources( shared
	PUBLIC
		FILE_SET public_headers
		TYPE HEADERS
		BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/..
		FILES
			logging.h
)

target_sources( shared
	INTERFACE
		FILE_SET generated_headers
		TYPE HEADERS
		BASE_DIRS ${CMAKE_CURRENT_BINARY_DIR}
		FILES
			${CMAKE_CURRENT_BINARY_DIR}/datasets.h
)

target_include_directories( shared
	INTERFACE
		$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
		$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/..>
		$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

install( TARGETS shared
	EXPORT sharedTargets
	RUNTIME DESTINATION bin COMPONENT ${CMAKE_INSTALL_LIBDIR}
	LIBRARY DESTINATION lib COMPONENT ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION lib COMPONENT ${CMAKE_INSTALL_BINDIR}
	FILE_SET public_headers DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/shared
	FILE_SET generated_headers DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/shared
)

#
# Packaging
#
install( EXPORT sharedTargets
	FILE sharedTargets.cmake
	NAMESPACE shared::
	DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/shared
)