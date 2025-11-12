#
# writekey executable
#

add_executable( writekey )
target_sources( writekey
	PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/main.c
)

target_link_libraries( writekey PRIVATE loadkey )
target_compile_definitions( writekey
	PRIVATE
		"KEY_WRAPPED={${KEY_WRAPPED_BYTES}}"
)

install( TARGETS writekey
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)