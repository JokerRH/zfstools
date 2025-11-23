if( NOT DEFINED POOL_NAME )
	message( FATAL_ERROR "POOL_NAME not defined" )
endif( )

if( NOT DEFINED POOL_ID )
	message( FATAL_ERROR "POOL_ID not defined" )
endif( )

if( NOT DEFINED POOL_VDEVS )
	message( FATAL_ERROR "POOL_VDEVS not defined" )
endif( )

if( NOT DEFINED ID_KEY )
	message( FATAL_ERROR "ID_KEY not defined" )
endif( )

if( NOT DEFINED PEM )
	message( FATAL_ERROR "PEM not defined" )
endif( )

if( NOT DEFINED DATASET_CALLS )
	message( FATAL_ERROR "DATASETS not defined" )
endif( )

#
# zfsmount executable
#

add_executable( zfsmount )
target_sources( zfsmount
	PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/main.c
)

target_link_libraries( zfsmount PRIVATE loadkey zfstools shared )

target_compile_definitions( zfsmount
	PRIVATE
		POOL_NAME=${POOL_NAME}
		POOL_ID=${POOL_ID}ull
		POOL_VDEVS=${VDEV_STRING}
		ID_KEY=0x${ID_KEY}
		"PEM={${PEM_BYTES}}"
)

install( TARGETS zfsmount
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)