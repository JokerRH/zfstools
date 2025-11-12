#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <loadkey/loadkey.h>

static block256_t g_ymmKey = { KEY_WRAPPED };

int main( int argc, char *argv[ ] )
{
	if( argc < 2 )
	{
		fputs( "Insufficient arguments. Please provide the file that shall receive the unwrapped binary key.\n", stderr );
		return EXIT_FAILURE;
	}

	const int fd = open( argv[ 1 ], O_WRONLY | O_CREAT | O_TRUNC, 0600 );
	if( fd < 0 )
	{
		fprintf( stderr, "Failed to open output file \"%s\".\n", argv[ 1 ] );
		return EXIT_FAILURE;
	}

	if( !LoadKey( &g_ymmKey ) )
		goto ERROR_AFTER_FILE;

	if( write( fd, g_ymmKey.ab, sizeof( g_ymmKey ) ) != sizeof( g_ymmKey ) )
	{
		fprintf( stderr, "Failed to write unwrapped key to output file \"%s\".\n", argv[ 1 ] );
		goto ERROR_AFTER_FILE;
	}

	if( close( fd ) < 0 )
	{
		fprintf( stderr, "Failed to close output file \"%s\".\n", argv[ 1 ] );
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;

ERROR_AFTER_FILE:
	close( fd );
	return EXIT_FAILURE;
}