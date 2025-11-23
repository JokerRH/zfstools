#pragma once
#include <stdbool.h>

#if defined( _MSC_VER )
#	define ALIGN16 __declspec(align(16))
#elif defined( __GNUC__ )
#	define ALIGN16 __attribute__((aligned(16)))
#endif

typedef ALIGN16 struct
{
	unsigned char ab[ 32 ];
} block256_t;

typedef struct
{
	unsigned char ab[ 65 ];
} pem_t;

typedef struct { void *fSuccess; long _2; } yksession_t;

unsigned YK_ReadPIN( char pin[ 8 ] );
bool YK_StartPCSCD( void );
void YK_StopPCSCD( void );
bool YK_MakeYubikeyDev( void );

bool YK_Login( yksession_t *pSession, const char *abPIN, unsigned numDigits );
void YK_Logout( const yksession_t *pSession );
bool YK_LoadPEM( const yksession_t *pSession, unsigned char idKey, pem_t *pPEM );
bool YK_LoadKEK( const yksession_t *const pSession, const unsigned char idKey, const pem_t *const pPEM, block256_t *const pymmKEK );
void YK_Unwrap( block256_t *pymmKey, block256_t ymmKEK );

#ifndef WIN32
#include <fcntl.h>
int mkdirp( char *szPath, mode_t mode );
#endif