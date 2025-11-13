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

#ifndef WIN32
#	define stricmp	strcasecmp
#endif

static bool LoadECPoint( unsigned char abPoint[ 67 ], const char *const abPIN, const unsigned numDigits, const unsigned idKey )
{
	CK_FUNCTION_LIST_PTR funcs;
	if( C_GetFunctionList( &funcs ) != CKR_OK )
	{
		fprintf( stderr, "Failed to load ykcs11 function list.\n" );
		return false;
	}

	if( funcs->C_Initialize( NULL ) != CKR_OK )
	{
		fprintf( stderr, "Failed to initialize ykcs11.\n" );
		return false;
	}

	//Open session
	CK_SESSION_HANDLE hSession;
	{
		CK_SLOT_ID idSlot;
		CK_ULONG numSlots = 1;
		switch( funcs->C_GetSlotList( CK_TRUE, &idSlot, &numSlots ) )
		{
		case CKR_OK:
			break;
		case CKR_BUFFER_TOO_SMALL:
			fprintf( stderr, "More than one ykcs11 slot found. Please ensure only one is present.\n" );
			goto ERROR_AFTER_INIT;
		default:
			fprintf( stderr, "Failed to fetch ykcs11 slot.\n" );
			goto ERROR_AFTER_INIT;
		}
		
		if( !numSlots )
		{
			fprintf( stderr, "No ykcs11 slot available.\n" );
			goto ERROR_AFTER_INIT;
		}

		if( funcs->C_OpenSession( idSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSession ) != CKR_OK )
		{
			fprintf( stderr, "Failed to open ykcs11 session.\n" );
			goto ERROR_AFTER_INIT;
		}
	}

	if( funcs->C_Login( hSession, CKU_USER, (char *) abPIN, numDigits ) != CKR_OK )
	{
		fprintf( stderr, "Failed to login in ykcs11 session.\n" );
		goto ERROR_AFTER_SESSION;
	}

	//Find the public key
	CK_OBJECT_HANDLE hKeyPublic;
	{
		CK_OBJECT_CLASS key_class = CKO_PUBLIC_KEY;
		CK_KEY_TYPE key_type = CKK_EC;
		CK_ATTRIBUTE key_template[ ] =
		{
			{ CKA_CLASS, &key_class, sizeof( key_class ) },
			{ CKA_KEY_TYPE, &key_type, sizeof( key_type ) },
			{ CKA_ID, (CK_VOID_PTR) &idKey, sizeof( unsigned char ) }
		};

		if( funcs->C_FindObjectsInit( hSession, key_template, sizeof( key_template ) / sizeof( CK_ATTRIBUTE ) ) != CKR_OK )
		{
			fprintf( stderr, "Failed to find public key.\n" );
			goto ERROR_AFTER_LOGIN;
		}

		CK_ULONG numFound;
		if( funcs->C_FindObjects( hSession, &hKeyPublic, 1, &numFound ) != CKR_OK || numFound != 1 )
		{
			fprintf( stderr, "Failed to find public key.\n" );
			goto ERROR_AFTER_LOGIN;
		}

		funcs->C_FindObjectsFinal( hSession );
	}

	CK_ATTRIBUTE ecPointAttr = { CKA_EC_POINT, NULL, 0 };
	if( funcs->C_GetAttributeValue( hSession, hKeyPublic, &ecPointAttr, 1 ) != CKR_OK )
	{
		fprintf( stderr, "Failed to get EC point attribute.\n" );
		goto ERROR_AFTER_LOGIN;
	}

	if( ecPointAttr.ulValueLen != 67 )
	{
		fprintf( stderr, "EC point attribute has length %u. Expected was 67.\n", ecPointAttr.ulValueLen );
		goto ERROR_AFTER_LOGIN;
	}

	ecPointAttr.pValue = abPoint;
	if( funcs->C_GetAttributeValue( hSession, hKeyPublic, &ecPointAttr, 1 ) != CKR_OK )
	{
		fprintf( stderr, "Failed to get EC point attribute.\n" );
		goto ERROR_AFTER_LOGIN;
	}

	funcs->C_Logout( hSession );
	funcs->C_CloseSession( hSession );
	funcs->C_Finalize( NULL );

	return true;

ERROR_AFTER_LOGIN:
	funcs->C_Logout( hSession );
ERROR_AFTER_SESSION:
	funcs->C_CloseSession( hSession );
ERROR_AFTER_INIT:
	funcs->C_Finalize( NULL );
	return false;
}

static bool LoadKEK_PEM( block256_t *const pKEK, const unsigned char idKey, const CK_UTF8CHAR_PTR abPIN, const size_t numDigits )
{
	CK_FUNCTION_LIST_PTR funcs;
	if( C_GetFunctionList( &funcs ) != CKR_OK )
	{
		fprintf( stderr, "Failed to load ykcs11 function list.\n" );
		return false;
	}

	if( funcs->C_Initialize( NULL ) != CKR_OK )
	{
		fprintf( stderr, "Failed to initialize ykcs11.\n" );
		return false;
	}

	//Open session
	CK_SESSION_HANDLE hSession;
	{
		CK_SLOT_ID idSlot;
		CK_ULONG numSlots = 1;
		switch( funcs->C_GetSlotList( CK_TRUE, &idSlot, &numSlots ) )
		{
		case CKR_OK:
			break;
		case CKR_BUFFER_TOO_SMALL:
			fprintf( stderr, "More than one ykcs11 slot found. Please ensure only one is present.\n" );
			goto ERROR_AFTER_INIT;
		default:
			fprintf( stderr, "Failed to fetch ykcs11 slot.\n" );
			goto ERROR_AFTER_INIT;
		}
		
		if( !numSlots )
		{
			fprintf( stderr, "No ykcs11 slot available.\n" );
			goto ERROR_AFTER_INIT;
		}

		if( funcs->C_OpenSession( idSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSession ) != CKR_OK )
		{
			fprintf( stderr, "Failed to open ykcs11 session.\n" );
			goto ERROR_AFTER_INIT;
		}
	}

	if( funcs->C_Login( hSession, CKU_USER, abPIN, numDigits ) != CKR_OK )
	{
		fprintf( stderr, "Failed to login in ykcs11 session.\n" );
		goto ERROR_AFTER_SESSION;
	}

	//Find private key
	CK_OBJECT_HANDLE hKeyPrivate;
	{
		CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
		CK_KEY_TYPE key_type = CKK_EC;
		CK_ATTRIBUTE key_template[ ] =
		{
			{ CKA_CLASS, &key_class, sizeof( key_class ) },
			{ CKA_KEY_TYPE, &key_type, sizeof( key_type ) },
			{ CKA_ID, (CK_VOID_PTR) &idKey, sizeof( unsigned char ) }
		};

		if( funcs->C_FindObjectsInit( hSession, key_template, sizeof( key_template ) / sizeof( CK_ATTRIBUTE ) ) != CKR_OK )
		{
			fprintf( stderr, "Failed to find private key.\n" );
			goto ERROR_AFTER_LOGIN;
		}

		CK_ULONG numFound;
		if( funcs->C_FindObjects( hSession, &hKeyPrivate, 1, &numFound ) != CKR_OK || numFound != 1 )
		{
			fprintf( stderr, "Failed to find private key.\n" );
			goto ERROR_AFTER_LOGIN;
		}

		funcs->C_FindObjectsFinal( hSession );
	}

	//Find the public key
	CK_OBJECT_HANDLE hKeyPublic;
	{
		CK_OBJECT_CLASS key_class = CKO_PUBLIC_KEY;
		CK_KEY_TYPE key_type = CKK_EC;
		CK_ATTRIBUTE key_template[ ] =
		{
			{ CKA_CLASS, &key_class, sizeof( key_class ) },
			{ CKA_KEY_TYPE, &key_type, sizeof( key_type ) },
			{ CKA_ID, (CK_VOID_PTR) &idKey, sizeof( unsigned char ) }
		};

		if( funcs->C_FindObjectsInit( hSession, key_template, sizeof( key_template ) / sizeof( CK_ATTRIBUTE ) ) != CKR_OK )
		{
			fprintf( stderr, "Failed to find public key.\n" );
			goto ERROR_AFTER_LOGIN;
		}

		CK_ULONG numFound;
		if( funcs->C_FindObjects( hSession, &hKeyPublic, 1, &numFound ) != CKR_OK || numFound != 1 )
		{
			fprintf( stderr, "Failed to find public key.\n" );
			goto ERROR_AFTER_LOGIN;
		}

		funcs->C_FindObjectsFinal( hSession );
	}

	CK_ATTRIBUTE ecPointAttr = { CKA_EC_POINT, NULL, 0 };
	if( funcs->C_GetAttributeValue( hSession, hKeyPublic, &ecPointAttr, 1 ) != CKR_OK )
	{
		fprintf( stderr, "Failed to get EC point attribute.\n" );
		goto ERROR_AFTER_LOGIN;
	}

	if( ecPointAttr.ulValueLen != 67 )
	{
		fprintf( stderr, "EC point attribute has length %u. Expected was 67.\n", ecPointAttr.ulValueLen );
		goto ERROR_AFTER_LOGIN;
	}

	unsigned char abPoint[ 67 ];
	ecPointAttr.pValue = abPoint;
	if( funcs->C_GetAttributeValue( hSession, hKeyPublic, &ecPointAttr, 1 ) != CKR_OK )
	{
		fprintf( stderr, "Failed to get EC point attribute.\n" );
		goto ERROR_AFTER_LOGIN;
	}

	//Derive KEK from private key
	CK_OBJECT_HANDLE hDerived;
	{
		CK_ECDH1_DERIVE_PARAMS ecdh_params =
		{
			.kdf = CKD_NULL,
			.pPublicData = abPoint + 2,
			.ulPublicDataLen = 65
		};

		CK_MECHANISM mech =
		{
			.mechanism = CKM_ECDH1_DERIVE,
			.pParameter = &ecdh_params,
			.ulParameterLen = sizeof( ecdh_params )
		};

		//Template for the derived object
		CK_OBJECT_CLASS derived_class = CKO_SECRET_KEY;
		CK_KEY_TYPE derived_type = CKK_GENERIC_SECRET;
		CK_ATTRIBUTE derived_tmpl[ ] =
		{
			{ CKA_CLASS, &derived_class, sizeof( derived_class ) },
			{ CKA_KEY_TYPE, &derived_type, sizeof( derived_type ) }
		};

		if( funcs->C_DeriveKey( hSession, &mech, hKeyPrivate, derived_tmpl, sizeof( derived_tmpl ) / sizeof( CK_ATTRIBUTE ), &hDerived ) != CKR_OK )
		{
			fprintf( stderr, "Failed to derive KEK.\n" );
			goto ERROR_AFTER_LOGIN;
		}
	}

	{
		CK_ATTRIBUTE attr = { CKA_VALUE, pKEK->ab, sizeof( block256_t ) };
		if( funcs->C_GetAttributeValue( hSession, hDerived, &attr, sizeof( attr ) / sizeof( CK_ATTRIBUTE ) ) )
		{
			fprintf( stderr, "Failed to extract KEK.\n" );
			goto ERROR_AFTER_LOGIN;
		}
	}

	funcs->C_Logout( hSession );
	funcs->C_CloseSession( hSession );
	funcs->C_Finalize( NULL );

	return true;

ERROR_AFTER_LOGIN:
	funcs->C_Logout( hSession );
ERROR_AFTER_SESSION:
	funcs->C_CloseSession( hSession );
ERROR_AFTER_INIT:
	funcs->C_Finalize( NULL );
	return false;
}

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
	if( argc < 3 )
	{
		fputs( "Insufficient arguments. ", stderr );
		goto PRINT_ARGS;
	}

	unsigned long idKey;
	{
		char *szEnd;
		idKey = strtoul( argv[ 2 ], &szEnd, 16 );
		if( szEnd[ 0 ] )
		{
			fprintf( stderr, "Key ID \"%s\" is not a valid number.\n", argv[ 2 ] );
			return EXIT_FAILURE;
		}
	}

	if( !stricmp( argv[ 1 ], "pem" ) )
	{
		char abPIN[ 8 ];
		const unsigned numDigits = ReadPIN( abPIN );

		unsigned char abPEM[ 67 ];
		if( !LoadECPoint( abPEM, abPIN, numDigits, idKey ) )
			return EXIT_FAILURE;

		fputs( "PEM: ", stdout );
		for( unsigned u = 2; u < 67; ++u )
			printf( "%02X", abPEM[ u ] );
		puts( "" );
	}
	else
	{
		if( argc < 4 )
		{
			fputs( "Insufficient arguments. ", stderr );
			goto PRINT_ARGS;
		}

		block256_t ymmKey;
		if( !ReadKey( &ymmKey, argv[ 3 ]) )
			return EXIT_FAILURE;

		if( !stricmp( argv[ 1 ], "wrap" ) )
		{
			char abPIN[ 8 ];
			const unsigned numDigits = ReadPIN( abPIN );

			block256_t ymmKEK;
			if( !LoadKEK_PEM( &ymmKEK, idKey, abPIN, numDigits ) )
				return EXIT_FAILURE;

			block256_t ymmWrapped;
			Decrypt256_256( ymmKey.ab, ymmWrapped.ab, ymmKEK.ab );

			fputs( "Wrapped key: ", stdout );
			for( unsigned u = 0; u < 32; ++u )
				printf( "%02X", ymmWrapped.ab[ u ] );
			puts( "" );
		}
		else if( !stricmp( argv[ 1 ], "unwrap" ) )
		{
			char abPIN[ 8 ];
			const unsigned numDigits = ReadPIN( abPIN );

			block256_t ymmKEK;
			if( !LoadKEK_PEM( &ymmKEK, idKey, abPIN, numDigits ) )
				return EXIT_FAILURE;

			block256_t ymmUnwrapped;
			Encrypt256_256( ymmKey.ab, ymmUnwrapped.ab, ymmKEK.ab );

			fputs( "Unwrapped key: ", stdout );
			for( unsigned u = 0; u < 32; ++u )
				printf( "%02X", ymmUnwrapped.ab[ u ] );
			puts( "" );
		}
		else
		{
PRINT_ARGS:
			fputs( "Arguments are:\n\tpem [key id]\n\twrap [key id] [key]\n\tunwrap [key id] [key]\n", stderr );
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}