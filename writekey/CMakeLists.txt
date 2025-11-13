if( NOT DEFINED ID_KEY )
	message( FATAL_ERROR "ID_KEY not defined" )
endif( )

if( NOT DEFINED PEM )
	message( FATAL_ERROR "PEM not defined" )
endif( )

if( NOT DEFINED KEY_WRAPPED )
	message( FATAL_ERROR "KEY_WRAPPED not defined" )
endif( )

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
		ID_KEY=0x${ID_KEY}
		"PEM={${PEM_BYTES}}"
		"KEY_WRAPPED={${KEY_WRAPPED_BYTES}}"
)

install( TARGETS writekey
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)