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

static const pem_t g_pem = { PEM };

#define DATASET( szDataset, ymmKey, szPath )	if( !WriteKey( ymmKEK, szDataset, ymmKey, szPath ) ) iRet = EXIT_FAILURE;

bool WriteKey( const block256_t ymmKEK, const char *const szDataset, block256_t ymmKey, const char *const szPath )
{
	const int fd = open( szPath, O_WRONLY | O_CREAT | O_TRUNC, 0600 );
	if( fd < 0 )
	{
		syslog( LOG_ERR, "Failed to open dataset \"%s\" key output file \"%s\".", szDataset, szPath );
		return false;
	}

	YK_Unwrap( &ymmKey, ymmKEK );

	if( write( fd, ymmKey.ab, sizeof( ymmKey ) ) != sizeof( ymmKey ) )
	{
		syslog( LOG_ERR, "Failed to write dataset \"%s\" key to output file \"%s\".", szDataset, szPath );
		close( fd );
		return false;
	}

	if( close( fd ) < 0 )
	{
		syslog( LOG_ERR, "Failed to close dataset \"%s\" key output file \"%s\".", szDataset, szPath );
		return false;
	}

	return true;
}

int main( int argc, char *argv[ ] )
{
	openlog( "writekey", LOG_CONS | LOG_PERROR, LOG_USER );
	int iRet = EXIT_SUCCESS;

	if( !YK_StartPCSCD( ) )
	{
		iRet = EXIT_FAILURE;
		goto ERROR_AFTER_LOG;
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

	//Automatically generated DATASET calls
#	include <shared/datasets.h>

ERROR_AFTER_LOGIN:
	YK_Logout( &session );
ERROR_AFTER_PCSCD:
	YK_StopPCSCD( );
ERROR_AFTER_LOG:
	closelog( );
	return iRet;
}