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

unsigned ReadPIN( char pin[ 8 ] );
bool LoadKey( block256_t *pymmKey, const pem_t *pPEM, unsigned char idKey );

#ifndef WIN32
#include <fcntl.h>
int mkdirp( char *szPath, mode_t mode );
#endif