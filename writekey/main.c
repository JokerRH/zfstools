#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <loadkey/loadkey.h>
#include "logging.h"

#ifdef WIN32
#	include <io.h>
#else
#	include <unistd.h>
#endif

static block256_t g_ymmKey = { KEY_WRAPPED };
static const pem_t g_pem = { PEM };

int main( int argc, char *argv[ ] )
{
	openlog( "writekey", LOG_CONS | LOG_PERROR, LOG_USER );

	if( argc < 2 )
	{
		syslog( LOG_ERR, "Insufficient arguments. Please provide the file that shall receive the unwrapped binary key." );
		goto ERROR_AFTER_LOG;
	}

	const int fd = open( argv[ 1 ], O_WRONLY | O_CREAT | O_TRUNC, 0600 );
	if( fd < 0 )
	{
		syslog( LOG_ERR, "Failed to open output file \"%s\".", argv[ 1 ] );
		goto ERROR_AFTER_LOG;
	}

	if( !LoadKey( &g_ymmKey, &g_pem, ID_KEY ) )
		goto ERROR_AFTER_FILE;

	if( write( fd, g_ymmKey.ab, sizeof( g_ymmKey ) ) != sizeof( g_ymmKey ) )
	{
		syslog( LOG_ERR, "Failed to write unwrapped key to output file \"%s\".", argv[ 1 ] );
		goto ERROR_AFTER_FILE;
	}

	if( close( fd ) < 0 )
	{
		syslog( LOG_ERR, "Failed to close output file \"%s\".", argv[ 1 ] );
		goto ERROR_AFTER_LOG;
	}

	closelog( );
	return EXIT_SUCCESS;

ERROR_AFTER_FILE:
	close( fd );
ERROR_AFTER_LOG:
	closelog( );
	return EXIT_FAILURE;
}