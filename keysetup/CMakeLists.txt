#
# keysetup executable
#

find_package( PkgConfig REQUIRED )
pkg_check_modules( YKCS11 REQUIRED IMPORTED_TARGET ykcs11 )

add_executable( keysetup )
target_sources( keysetup
	PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/main.c
		${CMAKE_CURRENT_SOURCE_DIR}/Rijndael.h
		${CMAKE_CURRENT_SOURCE_DIR}/Rijndael.c
)

target_include_directories( keysetup PRIVATE ${CMAKE_SOURCE_DIR}/shared )
target_link_libraries( keysetup PRIVATE loadkey )
target_link_libraries( keysetup PRIVATE PkgConfig::YKCS11 )

install( TARGETS keysetup
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)