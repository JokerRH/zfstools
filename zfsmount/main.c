#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <loadkey/loadkey.h>
#include <zfstools/zfstools.h>

#define XSTR( a ) STR( a )
#define STR( a ) #a

static block256_t g_ymmKey = { KEY_WRAPPED };
static const pem_t g_PEM = { PEM };

int main( int argc, char *argv[ ] )
{
	openlog( "zfsmount", LOG_CONS, LOG_DAEMON );

	if( !LoadKey( &g_ymmKey, &g_PEM, ID_KEY ) )
		goto ERROR_AFTER_LOG;

	if( libzfs_core_init( ) )
	{
		syslog( LOG_ERR, "Failed to initialize ZFS core." );
		goto ERROR_AFTER_LOG;
	}

	//This is basically what libzfs_core_init also does, except that libzfs_core does not expose g_fd.
	const int fdZFS = open( ZFS_DEV, O_RDWR | O_CLOEXEC );
	if( fdZFS < 0 )
	{
		syslog( LOG_ERR, "Failed to open handle to ZFS device." );
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

	closelog( );
	return EXIT_SUCCESS;

ERROR_AFTER_FD:
	(void) close( fdZFS );
ERROR_AFTER_INIT:
	libzfs_core_fini( );
ERROR_AFTER_LOG:
	closelog( );
	return EXIT_FAILURE;
}