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
	int iRet = EXIT_SUCCESS;

	if( argc < 2 )
	{
		syslog( LOG_ERR, "Insufficient arguments. Please provide the file that shall receive the unwrapped binary key." );
		iRet = EXIT_FAILURE;
		goto ERROR_AFTER_LOG;
	}

	const int fd = open( argv[ 1 ], O_WRONLY | O_CREAT | O_TRUNC, 0600 );
	if( fd < 0 )
	{
		syslog( LOG_ERR, "Failed to open output file \"%s\".", argv[ 1 ] );
		iRet = EXIT_FAILURE;
		goto ERROR_AFTER_LOG;
	}

	if( !YK_StartPCSCD( ) )
	{
		iRet = EXIT_FAILURE;
		goto ERROR_AFTER_FILE;
	}
	if( !YK_MakeYubikeyDev( ) )
	{
		iRet = EXIT_FAILURE;
		goto ERROR_AFTER_PCSCD;
	}

	char abPIN[ 8 ];
	const unsigned numDigits = YK_ReadPIN( abPIN );

	yksession_t session;
	if( !YK_Login( &session, abPIN, numDigits ) )
	{
		iRet = EXIT_FAILURE;
		goto ERROR_AFTER_PCSCD;
	}

	block256_t ymmKEK;
	if( !YK_LoadKEK( &session, ID_KEY, &g_pem, &ymmKEK ) )
	{
		iRet = EXIT_FAILURE;
		goto ERROR_AFTER_LOGIN;
	}

	YK_Unwrap( &g_ymmKey, ymmKEK );

	if( write( fd, g_ymmKey.ab, sizeof( g_ymmKey ) ) != sizeof( g_ymmKey ) )
	{
		syslog( LOG_ERR, "Failed to write unwrapped key to output file \"%s\".", argv[ 1 ] );
		iRet = EXIT_FAILURE;
		goto ERROR_AFTER_LOGIN;
	}

ERROR_AFTER_LOGIN:
	YK_Logout( &session );
ERROR_AFTER_PCSCD:
	YK_StopPCSCD( );
ERROR_AFTER_FILE:
	close( fd );
ERROR_AFTER_LOG:
	closelog( );
	return iRet;
}