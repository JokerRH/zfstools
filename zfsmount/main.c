#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <loadkey/loadkey.h>
#include <zfstools/zfstools.h>

#define XSTR( a ) STR( a )
#define STR( a ) #a

static block256_t g_ymmKey = { KEY_WRAPPED };

int main( int argc, char *argv[ ] )
{
	if( !LoadKey( &g_ymmKey ) )
		return EXIT_FAILURE;

	if( libzfs_core_init( ) )
	{
		fputs( "Failed to initialize ZFS core.\n", stderr );
		return EXIT_FAILURE;
	}

	//This is basically what libzfs_core_init also does, except that libzfs_core does not expose g_fd.
	const int fdZFS = open( ZFS_DEV, O_RDWR | O_CLOEXEC );
	if( fdZFS < 0 )
	{
		fputs( "Failed to open handle to ZFS device.\n", stderr );
		goto ERROR_AFTER_INIT;
	}

	if( !ImportPool( fdZFS, XSTR( POOL_VDEVS ), XSTR( POOL_NAME ), POOL_ID ) )
		goto ERROR_AFTER_FD;

	if( !LoadPoolKey( XSTR( POOL_NAME ), g_ymmKey ) )	
		goto ERROR_AFTER_FD;

	if( !MountPool( fdZFS, XSTR( POOL_NAME ) ) )
		goto ERROR_AFTER_FD;

	(void) close( fdZFS );
	libzfs_core_fini( );

	printf( "Done!\n" );
	return EXIT_SUCCESS;

ERROR_AFTER_FD:
	(void) close( fdZFS );
ERROR_AFTER_INIT:
	libzfs_core_fini( );
	return EXIT_FAILURE;
}