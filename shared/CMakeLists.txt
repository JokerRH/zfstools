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
	EXPORT ${ZFSTOOLS_EXPORT_SET}
	RUNTIME DESTINATION bin
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib
	FILE_SET public_headers DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/shared"
	FILE_SET generated_headers DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/shared"
)