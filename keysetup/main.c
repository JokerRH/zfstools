/* Arguments:
	pem [key id]
	wrap [key id] [key]
	unwrap [key id] [key]
*/

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <ykpiv/pkcs11y.h>
#include <loadkey/loadkey.h>
#include "Rijndael.h"
#include "logging.h"

#ifndef WIN32
#	define stricmp	strcasecmp
#endif

static bool ReadKey( block256_t *const ymmKey, const char *sz )
{
	if( strlen( sz ) != 64 )
	{
		puts( "Key argument must be exactly 64 hexadecimal characters." );
		return false;
	}

	unsigned uValue;
	for( unsigned u = 0; u < 32; ++u )
	{
		if( sscanf( &sz[ u * 2 ], "%2x", &uValue ) != 1 )
		{
			puts( "Key argument must be exactly 64 hexadecimal characters." );
			return false;
		}
		ymmKey->ab[ u ] = (unsigned char) uValue;
	}

	return true;
}

int main( int argc, char *argv[ ] )
{
	enum
	{
		CMD_PEM,
		CMD_WRAP,
		CMD_UNWRAP,
		CMD_CWRAP,
		CMD_CUNWRAP
	} eCmd;

	//Initialize syslog for loadkey
	openlog( "keysetup", LOG_CONS | LOG_PERROR, LOG_USER );
	int iRet = EXIT_SUCCESS;

	if( argc < 3 )
	{
		fputs( "Insufficient arguments. ", stderr );
		goto PRINT_ARGS;
	}

	if( !stricmp( argv[ 1 ], "pem" ) )
		eCmd = CMD_PEM;
	else
	{
		if( argc < 4 )
		{
			fputs( "Insufficient arguments. ", stderr );
			goto PRINT_ARGS;
		}

		if( !stricmp( argv[ 1 ], "wrap" ) )
			eCmd = CMD_WRAP;
		else if( !stricmp( argv[ 1 ], "unwrap" ) )
			eCmd = CMD_UNWRAP;
		else if( !stricmp( argv[ 1 ], "cwrap" ) )
			eCmd = CMD_CWRAP;
		else if( !stricmp( argv[ 1 ], "cunwrap" ) )
			eCmd = CMD_CUNWRAP;
		else
		{
PRINT_ARGS:
			fputs( "Arguments are:\n\tpem [key id]\n\twrap [key id] [key]\n\tunwrap [key id] [key]\n\tcwrap [kek] [key]\n\tcunwrap [kek] [key]\n", stderr );
			iRet = EXIT_FAILURE;
			goto ERROR_AFTER_LOG;
		}
	}

	block256_t ymmKEK;
	block256_t ymmKey;
	if( eCmd == CMD_CWRAP || eCmd == CMD_CUNWRAP )
	{
		if( !ReadKey( &ymmKEK, argv[ 2 ]) )
		{
			iRet = EXIT_FAILURE;
			goto ERROR_AFTER_LOGIN;
		}

		if( !ReadKey( &ymmKey, argv[ 3 ]) )
		{
			iRet = EXIT_FAILURE;
			goto ERROR_AFTER_LOGIN;
		}

		goto WRAP_UNWRAP_KEY;
	}

	unsigned char idKey;
	{
		char *szEnd;
		const unsigned long u = strtoul( argv[ 2 ], &szEnd, 16 );
		if( szEnd[ 0 ] )
		{
			fprintf( stderr, "Key ID \"%s\" is not a valid number.\n", argv[ 2 ] );
			iRet = EXIT_FAILURE;
			goto ERROR_AFTER_LOG;
		}

		if( u > 0xFF )
		{
			fprintf( stderr, "Key ID \"%s\" is too large.\n", argv[ 2 ] );
			iRet = EXIT_FAILURE;
			goto ERROR_AFTER_LOG;
		}

		idKey = (unsigned char) u;
	}

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

	pem_t pem;
	if( !YK_LoadPEM( &session, idKey, &pem ) )
	{
		iRet = EXIT_FAILURE;
		goto ERROR_AFTER_LOGIN;
	}

	if( eCmd == CMD_PEM )
	{
		fputs( "PEM: ", stdout );
		for( unsigned u = 0; u < sizeof( pem_t ); ++u )
			printf( "%02X", pem.ab[ u ] );
		puts( "" );
	}
	else
	{
		if( !ReadKey( &ymmKey, argv[ 3 ]) )
		{
			iRet = EXIT_FAILURE;
			goto ERROR_AFTER_LOGIN;
		}

		if( !YK_LoadKEK( &session, idKey, &pem, &ymmKEK ) )
		{
			iRet = EXIT_FAILURE;
			goto ERROR_AFTER_LOGIN;
		}

WRAP_UNWRAP_KEY:
		block256_t ymmOut;
		switch( eCmd )
		{
		case CMD_WRAP:
		case CMD_CWRAP:
			Decrypt256_256( ymmKey.ab, ymmOut.ab, ymmKEK.ab );
			fputs( "Wrapped key: ", stdout );
			break;
		case CMD_UNWRAP:
		case CMD_CUNWRAP:
			Encrypt256_256( ymmKey.ab, ymmOut.ab, ymmKEK.ab );
			fputs( "Unwrapped key: ", stdout );
			break;
		default:
			goto ERROR_AFTER_LOGIN;
		}

		for( unsigned u = 0; u < 32; ++u )
			printf( "%02X", ymmOut.ab[ u ] );
		puts( "" );
	}

ERROR_AFTER_LOGIN:
	if( eCmd != CMD_CWRAP && eCmd != CMD_CUNWRAP )
		YK_Logout( &session );
ERROR_AFTER_PCSCD:
	if( eCmd != CMD_CWRAP && eCmd != CMD_CUNWRAP )
		YK_StopPCSCD( );
ERROR_AFTER_LOG:
	closelog( );
	return iRet;
}