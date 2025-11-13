#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <ykpiv/pkcs11y.h>
#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>
#include "loadkey.h"

#ifdef WIN32
#	include <Windows.h>
#else
#	include <unistd.h>
#	include <termios.h>
#	include <linux/prctl.h>
#	include <sys/prctl.h>
#	include <sys/stat.h>
#	include <sys/sysmacros.h>
#	include <sys/types.h>
#	include <dirent.h>
#endif

#define USB_DEV_ROOT	"/sys/bus/usb/devices/"
#define USB_DEV_NODE	"/dev/bus/usb/"
#define YUBIKEY_VENDOR	"1050"

#define XMMLO( ymm )	( ( (__m128i *) &( ymm ) )[ 0 ] )
#define XMMHI( ymm )	( ( (__m128i *) &( ymm ) )[ 1 ] )

unsigned ReadPIN( char pin[ 8 ] )
{
#ifdef WIN32
	const HANDLE hStdin = GetStdHandle( STD_INPUT_HANDLE );

	//Save original console mode
	DWORD dwMode;
	GetConsoleMode( hStdin, &dwMode );
	const DWORD dwPreviousMode = dwMode;

	// Disable line input and echo
	dwMode &= ~( ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT );
	SetConsoleMode( hStdin, dwMode );

	fputs( "Enter YubiKey PIN (6-8 digits): ", stdout );
	fflush( stdout );

	unsigned numDigits = 0;
	while( true )
	{
		INPUT_RECORD ir;
		DWORD count;

		ReadConsoleInput( hStdin, &ir, 1, &count );

		if( ir.EventType != KEY_EVENT || !ir.Event.KeyEvent.bKeyDown )
			continue;  //Only process key-down events

		const char c = ir.Event.KeyEvent.uChar.AsciiChar;
		if( c >= '0' && c <= '9' && numDigits < 8 )
		{
			pin[ numDigits++ ] = c;
			putchar( '*' );
			fflush( stdout );
		}
		else if( ( c == '\r' || c == '\n' ) && numDigits >= 6 )
		{
			putchar( '\n' );
			break;
		}
		else if( ir.Event.KeyEvent.wVirtualKeyCode == VK_BACK && numDigits > 0 )
		{
			--numDigits;
			printf( "\b \b" );
			fflush( stdout );
		}
	}

	// Restore original console mode
	SetConsoleMode( hStdin, dwPreviousMode );
	return numDigits;
#else
	struct termios oldt;
	{
		tcgetattr( STDIN_FILENO, &oldt );	//Save original configuration
		
		struct termios newt = oldt;
		newt.c_lflag &= ~( ICANON | ECHO );	//Disable canonical mode & echo
		newt.c_cc[ VMIN ] = 1;				// read returns after 1 char
		newt.c_cc[ VTIME ] = 0;				// no timeout
		tcsetattr( STDIN_FILENO, TCSANOW, &newt );
	}

	fputs( "Enter YubiKey PIN (6-8 digits): ", stdout );
	fflush( stdout );

	unsigned numDigits = 0;
	while( 1 )
	{
		const int c = getchar( );
		if( c >= '0' && c <= '9' && numDigits < 8 )
		{
			pin[ numDigits++ ] = c;
			putchar( '*' );
			fflush( stdout );
		}
		else if( c == '\n' && numDigits >= 6 )
		{
			putchar('\n');
			break;
		}
		else if( ( c == 127 || c == 8 ) && numDigits > 0 )
		{
			//Backspace
			--numDigits;
			fputs( "\b \b", stdout );
			fflush( stdout );
		}
	}

	tcsetattr( STDIN_FILENO, TCSANOW, &oldt );
	return numDigits;
#endif
}

#ifndef WIN32
/*!
	\brief Searches for a USB device based on Yubico vendor id and creates the corresponding device node for it
*/
static bool MakeYubikeyDev( void )
{
	DIR *const pDir = opendir( USB_DEV_ROOT );
	if( !pDir )
	{
		fputs( "Failed to open usb sys device folder.\n", stderr );
		return false;
	}

	FILE *f;
	for( struct dirent *pEntry; pEntry = readdir( pDir ); )
	{
		if( pEntry->d_type != DT_LNK )
			continue;

		char szPath[ 256 ];
		char *szDetails;
		{
			const int numChars = snprintf( szPath, sizeof( szPath ), USB_DEV_ROOT "%s/idVendor", pEntry->d_name );
			if( numChars < 0 || numChars >= sizeof( szPath ) )
			{
				fputs( "Failed to format usb vendor path. Skipping device.\n", stderr );
				continue;
			}

			szDetails = szPath + numChars - sizeof( "idVendor" ) + 1;
		}

		//Check vendor id
		{
			f = fopen( szPath, "r" );
			if( !f )
				continue;

			{
				char abVendor[ sizeof( YUBIKEY_VENDOR ) ];
				if( !fgets( abVendor, sizeof( abVendor ), f ) )
				{
					fclose( f );
					fputs( "Failed to read usb vendor file. Skipping device.\n", stderr );
					continue;
				}
				
				if( feof( f ) )
				{
					fclose( f );
					fputs( "Reached end-of-file while reading usb vendor file. Skipping device.\n", stderr );
					continue;
				}

				if( memcmp( YUBIKEY_VENDOR, abVendor, sizeof( YUBIKEY_VENDOR ) ) )
					continue;
			}
			fclose( f );
		}

		//Read busnum
		int busnum;
		{
			//Ensure that the new value (here: "busnum") is no longer than "idVendor"!
			memcpy( szDetails, "busnum", sizeof( "busnum" ) );
			f = fopen( szPath, "r" );
			if( !f )
			{
				fputs( "Failed to open busnum of Yubico device. Skipping device.\n", stderr );
				continue;
			}

			if( fscanf( f, "%d", &busnum ) == EOF )
			{
				fputs( "Failed to read busnum of Yubico device. Skipping device.\n", stderr );
				fclose( f );
				continue;
			}
			fclose( f );
		}

		//Read devnum
		int devnum;
		{
			//Ensure that the new value (here: "devnum") is no longer than "idVendor"!
			memcpy( szDetails, "devnum", sizeof( "devnum" ) );
			f = fopen( szPath, "r" );
			if( !f )
			{
				fputs( "Failed to open devnum of Yubico device. Skipping device.\n", stderr );
				continue;
			}

			if( fscanf( f, "%d", &devnum ) == EOF )
			{
				fputs( "Failed to read devnum of Yubico device. Skipping device.\n", stderr );
				fclose( f );
				continue;
			}
			fclose( f );
		}

		// Calculate major/minor
		const int idMajor = 189;
		const int idMinor = ( busnum - 1 ) * 32 + ( devnum - 1 );

		//Create the /dev bus folder
		const int numBusChars = snprintf( szPath, sizeof( szPath ), USB_DEV_NODE "%03d", busnum );
		if( numBusChars < 0 || numBusChars >= sizeof( szPath ) )
		{
			fputs( "Failed to format device bus path.\n", stderr );
			goto ERROR_AFTER_DIR;
		}
		if( mkdir( szPath, 0755 ) && errno != EEXIST )
		{
			fputs( "Failed to create device bus path.\n", stderr );
			goto ERROR_AFTER_DIR;
		}

		//Create the device node
		{
			const int numChars = snprintf( szPath + numBusChars, sizeof( szPath ) - numBusChars, "/%03d", devnum );
			if( numChars < 0 || numChars >= sizeof( szPath ) - numBusChars )
			{
				fputs( "Failed to format device node path.\n", stderr );
				goto ERROR_AFTER_DIR;
			}
		}

		umask( 0000 );
		if( mknod( szPath, S_IFCHR | 0666, makedev( idMajor, idMinor ) ) && errno != EEXIST )
		{
			fprintf( stderr, "Failed to create device node \"%s\".\n", szPath );
			goto ERROR_AFTER_DIR;
		}

		closedir( pDir );
		return true;
	}

	fputs( "Failed to find a connected yubikey.\n", stderr );

ERROR_AFTER_DIR:
	closedir( pDir );
	return false;
}
#endif

static bool StartPCSCD( void )
{
#ifdef WIN32
	return true;
#else
	const pid_t ppid = getpid( );
	
	//Fork process to start pcscd
	{
		const pid_t pid = fork( );
		if( pid < 0 )
		{
			fputs( "Failed to fork process.\n", stderr );
			return false;
		}
		if( pid )
			return true;	//Parent process
	}
	//Child process from here on
	
	//Ensure the child terminates with the parent
	{
		if( prctl( PR_SET_PDEATHSIG, SIGTERM ) )
		{
			fputs( "Failed to set parent-death signal.\n", stderr );
			_exit( EXIT_FAILURE );
		}

		//Check if parent already died
		if( getppid( ) != ppid )
			_exit( EXIT_SUCCESS );
	}

	static char *const s_aszArg[ ] = { "-f", "-d", "--force-reader-polling", NULL };
	static char *const s_aszNullEnvP[ ] = { NULL };
	(void)! execve( "/sbin/pcscd", s_aszArg, s_aszNullEnvP );

	//If we reach this point, execve failed. Print error message and exit
	fputs( "Failed to start pcscd.\n", stderr );
	_exit( EXIT_FAILURE );
#endif
}

static bool LoadKEK( block256_t *const pKEK, const pem_t *const pPEM, const unsigned char idKey, const CK_UTF8CHAR_PTR abPIN, const size_t numDigits )
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

	//Derive KEK from private key
	CK_OBJECT_HANDLE hDerived;
	{
		CK_ECDH1_DERIVE_PARAMS ecdh_params =
		{
			.kdf = CKD_NULL,
			.pPublicData = pPEM->ab,
			.ulPublicDataLen = sizeof( *pPEM )
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

static void Rijndael256_256_EncryptSingle( block256_t *pData, block256_t key )
{
	__m128i tmp1, tmp2;
	const __m128i RIJNDAEL256_MASK = _mm_set_epi32( 0x03020d0c, 0x0f0e0908, 0x0b0a0504, 0x07060100 );
	const __m128i BLEND_MASK = _mm_set_epi32( 0x80000000, 0x80800000, 0x80800000, 0x80808000 );
	block256_t data = *pData;

	//Round 0 (initial xor)
	XMMLO( data ) = _mm_xor_si128( XMMLO( data ), XMMLO( key ) );
	XMMHI( data ) = _mm_xor_si128( XMMHI( data ), XMMHI( key ) );

	for( unsigned uRound = 1;; ++uRound )
	{
		//Blend to compensate for the shift rows shifts bytes between two 128 bit blocks
		tmp1 = _mm_blendv_epi8( XMMLO( data ), XMMHI( data ), BLEND_MASK );
		tmp2 = _mm_blendv_epi8( XMMHI( data ), XMMLO( data ), BLEND_MASK );

		//Shuffle that compensates for the additional shift in rows 3 and 4 as opposed to Rijndael128 (AES)
		XMMLO( data ) = _mm_shuffle_epi8( tmp1, RIJNDAEL256_MASK );
		XMMHI( data ) = _mm_shuffle_epi8( tmp2, RIJNDAEL256_MASK );

		//Perform key expansion
		{
			switch( uRound )
			{
			case  1: tmp1 = _mm_aeskeygenassist_si128( XMMHI( key ), 0x01 ); break;
			case  2: tmp1 = _mm_aeskeygenassist_si128( XMMHI( key ), 0x02 ); break;
			case  3: tmp1 = _mm_aeskeygenassist_si128( XMMHI( key ), 0x04 ); break;
			case  4: tmp1 = _mm_aeskeygenassist_si128( XMMHI( key ), 0x08 ); break;
			case  5: tmp1 = _mm_aeskeygenassist_si128( XMMHI( key ), 0x10 ); break;
			case  6: tmp1 = _mm_aeskeygenassist_si128( XMMHI( key ), 0x20 ); break;
			case  7: tmp1 = _mm_aeskeygenassist_si128( XMMHI( key ), 0x40 ); break;
			case  8: tmp1 = _mm_aeskeygenassist_si128( XMMHI( key ), 0x80 ); break;
			case  9: tmp1 = _mm_aeskeygenassist_si128( XMMHI( key ), 0x1B ); break;
			case 10: tmp1 = _mm_aeskeygenassist_si128( XMMHI( key ), 0x36 ); break;
			case 11: tmp1 = _mm_aeskeygenassist_si128( XMMHI( key ), 0x6C ); break;
			case 12: tmp1 = _mm_aeskeygenassist_si128( XMMHI( key ), 0xD8 ); break;
			case 13: tmp1 = _mm_aeskeygenassist_si128( XMMHI( key ), 0xAB ); break;
			case 14: tmp1 = _mm_aeskeygenassist_si128( XMMHI( key ), 0x4D ); break;
			}

			tmp1 = _mm_shuffle_epi32( tmp1, 0xff );
			tmp2 = _mm_slli_si128( XMMLO( key ), 0x4 );
			XMMLO( key ) = _mm_xor_si128( XMMLO( key ), tmp2 );
			tmp2 = _mm_slli_si128( tmp2, 0x4 );
			XMMLO( key ) = _mm_xor_si128( XMMLO( key ), tmp2 );
			tmp2 = _mm_slli_si128( tmp2, 0x4 );
			XMMLO( key ) = _mm_xor_si128( XMMLO( key ), tmp2 );
			XMMLO( key ) = _mm_xor_si128( XMMLO( key ), tmp1 );

			tmp2 = _mm_aeskeygenassist_si128( XMMLO( key ), 0x0 );
			tmp1 = _mm_shuffle_epi32( tmp2, 0xaa );
			tmp2 = _mm_slli_si128( XMMHI( key ), 0x4 );
			XMMHI( key ) = _mm_xor_si128( XMMHI( key ), tmp2 );
			tmp2 = _mm_slli_si128( tmp2, 0x4 );
			XMMHI( key ) = _mm_xor_si128( XMMHI( key ), tmp2 );
			tmp2 = _mm_slli_si128( tmp2, 0x4 );
			XMMHI( key ) = _mm_xor_si128( XMMHI( key ), tmp2 );
			XMMHI( key ) = _mm_xor_si128( XMMHI( key ), tmp1 );
		}

		if( uRound >= 14 )
			break;

		//This is the encryption step that includes sub bytes, shift rows, mix columns, xor with round key
		XMMLO( data ) = _mm_aesenc_si128( XMMLO( data ), XMMLO( key ) );
		XMMHI( data ) = _mm_aesenc_si128( XMMHI( data ), XMMHI( key ) );
	}

	//Last AES round
	XMMLO( *pData ) = _mm_aesenclast_si128( XMMLO( data ), XMMLO( key ) );
	XMMHI( *pData ) = _mm_aesenclast_si128( XMMHI( data ), XMMHI( key ) );
}

bool LoadKey( block256_t *const pymmKey, const const pem_t *const pPEM, const unsigned char idKey )
{
#ifdef DEBUG_KEY
	static const block256_t ymmKey = DEBUG_KEY;
	*pymmKey = ymmKey;
	return true;
#else

#ifndef WIN32
	if( !MakeYubikeyDev( ) )
		return false;
#endif

	if( !StartPCSCD( ) )
		return false;

	char pin[ 8 ];
	const unsigned numDigits = ReadPIN( pin );

	block256_t ymmKEK;
	if( !LoadKEK( &ymmKEK, pPEM, idKey, pin, numDigits ) )
		return false;

	Rijndael256_256_EncryptSingle( pymmKey, ymmKEK );
	return true;
#endif
}