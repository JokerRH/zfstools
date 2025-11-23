#include <ykpiv/pkcs11y.h>
#include <string.h>
#include <assert.h>
#include "loadkey.h"
#include "logging.h"

struct yksession_s
{
	CK_FUNCTION_LIST_PTR funcs;
	CK_SESSION_HANDLE hSession;
};
static_assert( sizeof( struct yksession_s ) == sizeof( yksession_t ), "yksession size mismatch" );

bool YK_Login( yksession_t *const pSession, const char *const abPIN, const unsigned numDigits )
{
#ifdef DEBUG_KEY
	return true;
#endif

	struct yksession_s *p = (struct yksession_s *) pSession;

	if( C_GetFunctionList( &p->funcs ) != CKR_OK )
	{
		syslog( LOG_ERR, "Failed to load ykcs11 function list." );
		return false;
	}

	if( p->funcs->C_Initialize( NULL ) != CKR_OK )
	{
		syslog( LOG_ERR, "Failed to initialize ykcs11." );
		return false;
	}

	//Open session
	{
		CK_SLOT_ID idSlot;
		CK_ULONG numSlots = 1;
		switch( p->funcs->C_GetSlotList( CK_TRUE, &idSlot, &numSlots ) )
		{
		case CKR_OK:
			break;
		case CKR_BUFFER_TOO_SMALL:
			syslog( LOG_ERR, "More than one ykcs11 slot found. Please ensure only one is present." );
			goto ERROR_AFTER_INIT;
		default:
			syslog( LOG_ERR, "Failed to fetch ykcs11 slot." );
			goto ERROR_AFTER_INIT;
		}
		
		if( !numSlots )
		{
			syslog( LOG_ERR, "No ykcs11 slot available." );
			goto ERROR_AFTER_INIT;
		}

		if( p->funcs->C_OpenSession( idSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &p->hSession ) != CKR_OK )
		{
			syslog( LOG_ERR, "Failed to open ykcs11 session." );
			goto ERROR_AFTER_INIT;
		}
	}

	if( p->funcs->C_Login( p->hSession, CKU_USER, (char *) abPIN, numDigits ) != CKR_OK )
	{
		syslog( LOG_ERR, "Failed to login in ykcs11 session." );
		goto ERROR_AFTER_SESSION;
	}

	return true;

ERROR_AFTER_SESSION:
	p->funcs->C_CloseSession( p->hSession );
ERROR_AFTER_INIT:
	p->funcs->C_Finalize( NULL );
	return false;
}

void YK_Logout( const yksession_t *const pSession )
{
#ifdef DEBUG_KEY
	return;
#endif

	struct yksession_s *p = (struct yksession_s *) pSession;
	p->funcs->C_Logout( p->hSession );
	p->funcs->C_CloseSession( p->hSession );
	p->funcs->C_Finalize( NULL );
}

bool YK_LoadPEM( const yksession_t *const pSession, const unsigned char idKey, pem_t *const pPEM )
{
#ifdef DEBUG_KEY
	return false;
#endif

	struct yksession_s *p = (struct yksession_s *) pSession;

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

		if( p->funcs->C_FindObjectsInit( p->hSession, key_template, sizeof( key_template ) / sizeof( CK_ATTRIBUTE ) ) != CKR_OK )
		{
			syslog( LOG_ERR, "Failed to find public key for key slot %u.\n", idKey );
			return false;
		}

		CK_ULONG numFound;
		if( p->funcs->C_FindObjects( p->hSession, &hKeyPublic, 1, &numFound ) != CKR_OK || numFound != 1 )
		{
			syslog( LOG_ERR, "Failed to find public key for key slot %u.\n", idKey );
			return false;
		}

		p->funcs->C_FindObjectsFinal( p->hSession );
	}

	CK_ATTRIBUTE ecPointAttr = { CKA_EC_POINT, NULL, 0 };
	if( p->funcs->C_GetAttributeValue( p->hSession, hKeyPublic, &ecPointAttr, 1 ) != CKR_OK )
	{
		syslog( LOG_ERR, "Failed to get EC point attribute for key slot %u.\n", idKey );
		return false;
	}

	if( ecPointAttr.ulValueLen != 67 )
	{
		syslog( LOG_ERR, "EC point attribute of key slot %u has length %lu. Expected was 67. Please choose a 256 bit ECC key.\n", idKey, ecPointAttr.ulValueLen );
		return false;
	}

	unsigned char abPoint[ 67 ];
	ecPointAttr.pValue = abPoint;
	if( p->funcs->C_GetAttributeValue( p->hSession, hKeyPublic, &ecPointAttr, 1 ) != CKR_OK )
	{
		syslog( LOG_ERR, "Failed to get EC point attribute for key slot %u.\n", idKey );
		return false;
	}

	memcpy( pPEM->ab, abPoint + 2, sizeof( pem_t ) );
	return true;
}

bool YK_LoadKEK( const yksession_t *const pSession, const unsigned char idKey, const pem_t *const pPEM, block256_t *const pymmKEK )
{
#ifdef DEBUG_KEY
	*pymmKEK = (block256_t) { DEBUG_KEY };
	return true;
#endif

	struct yksession_s *p = (struct yksession_s *) pSession;

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

		if( p->funcs->C_FindObjectsInit( p->hSession, key_template, sizeof( key_template ) / sizeof( CK_ATTRIBUTE ) ) != CKR_OK )
		{
			syslog( LOG_ERR, "Failed to find private key for key slot %u.", idKey );
			return false;
		}

		CK_ULONG numFound;
		if( p->funcs->C_FindObjects( p->hSession, &hKeyPrivate, 1, &numFound ) != CKR_OK || numFound != 1 )
		{
			syslog( LOG_ERR, "Failed to find private key for key slot %u.", idKey );
			return false;
		}

		p->funcs->C_FindObjectsFinal( p->hSession );
	}

	//Derive KEK from private key
	CK_OBJECT_HANDLE hDerived;
	{
		CK_ECDH1_DERIVE_PARAMS ecdh_params =
		{
			.kdf = CKD_NULL,
			.pPublicData = (char *) pPEM->ab,
			.ulPublicDataLen = sizeof( pem_t )
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

		if( p->funcs->C_DeriveKey( p->hSession, &mech, hKeyPrivate, derived_tmpl, sizeof( derived_tmpl ) / sizeof( CK_ATTRIBUTE ), &hDerived ) != CKR_OK )
		{
			syslog( LOG_ERR, "Failed to derive KEK from key slot %u.", idKey );
			return false;
		}
	}

	{
		CK_ATTRIBUTE attr = { CKA_VALUE, pymmKEK->ab, sizeof( block256_t ) };
		if( p->funcs->C_GetAttributeValue( p->hSession, hDerived, &attr, sizeof( attr ) / sizeof( CK_ATTRIBUTE ) ) )
		{
			syslog( LOG_ERR, "Failed to extract KEK from key slot %u.", idKey );
			return false;
		}
	}

	return true;
}