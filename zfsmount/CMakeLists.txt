#
# zfsmount executable
#

add_executable( zfsmount )
target_sources( zfsmount
	PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/main.c
)

target_link_libraries( zfsmount PRIVATE loadkey zfstools )

target_compile_definitions( zfsmount
	PRIVATE
		POOL_NAME=${POOL_NAME}
		POOL_ID=${POOL_ID}ull
		POOL_VDEVS=${POOL_VDEVS}
		"KEY_WRAPPED={${KEY_WRAPPED_BYTES}}"
)

install( TARGETS zfsmount
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)