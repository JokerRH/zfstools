#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "logging.h"

#define USB_DEV_ROOT	"/sys/bus/usb/devices/"
#define USB_DEV_NODE	"/dev/bus/usb/"
#define YUBIKEY_VENDOR	"1050"

/*!
	\param szPath	The path to create. On error, this string is shortened to the subpath that failed.
*/
int mkdirp( char *szPath, mode_t mode )
{
	for( char *pSeparator = szPath[ 0 ] == '/' ? szPath + 1 : szPath; *pSeparator; ++pSeparator )
	{
		if( pSeparator[ 0 ] != '/' )
			continue;

		pSeparator[ 0 ] = '\0';
		if( mkdir( szPath, mode ) && errno != EEXIST )
			return -1;

		pSeparator[ 0 ] = '/';
	}

	return mkdir( szPath, mode );
}

/*!
	\brief Searches for a USB device based on Yubico vendor id and creates the corresponding device node for it
*/
bool YK_MakeYubikeyDev( void )
{
	DIR *const pDir = opendir( USB_DEV_ROOT );
	if( !pDir )
	{
		syslog( LOG_ERR, "Failed to open usb sys device folder." );
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
				syslog( LOG_WARNING, "Failed to format usb vendor path. Skipping device." );
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
					syslog( LOG_WARNING, "Failed to read usb vendor file. Skipping device." );
					continue;
				}
				
				if( feof( f ) )
				{
					fclose( f );
					syslog( LOG_WARNING, "Reached end-of-file while reading usb vendor file. Skipping device." );
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
				syslog( LOG_WARNING, "Failed to open busnum of Yubico device. Skipping device." );
				continue;
			}

			if( fscanf( f, "%d", &busnum ) == EOF )
			{
				syslog( LOG_WARNING, "Failed to read busnum of Yubico device. Skipping device." );
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
				syslog( LOG_WARNING, "Failed to open devnum of Yubico device. Skipping device." );
				continue;
			}

			if( fscanf( f, "%d", &devnum ) == EOF )
			{
				syslog( LOG_WARNING, "Failed to read devnum of Yubico device. Skipping device." );
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
			syslog( LOG_ERR, "Failed to format device bus path." );
			goto ERROR_AFTER_DIR;
		}
		if( mkdirp( szPath, 0755 ) && errno != EEXIST )
		{
			syslog( LOG_ERR, "Failed to create device bus path \"%s\". Error code %d.", szPath, errno );
			goto ERROR_AFTER_DIR;
		}

		//Create the device node
		{
			const int numChars = snprintf( szPath + numBusChars, sizeof( szPath ) - numBusChars, "/%03d", devnum );
			if( numChars < 0 || numChars >= sizeof( szPath ) - numBusChars )
			{
				syslog( LOG_ERR, "Failed to format device node path." );
				goto ERROR_AFTER_DIR;
			}
		}

		umask( 0000 );
		if( mknod( szPath, S_IFCHR | 0666, makedev( idMajor, idMinor ) ) && errno != EEXIST )
		{
			syslog( LOG_ERR, "Failed to create device node \"%s\".", szPath );
			goto ERROR_AFTER_DIR;
		}

		closedir( pDir );
		return true;
	}

	syslog( LOG_ERR, "Failed to find a connected yubikey." );

ERROR_AFTER_DIR:
	closedir( pDir );
	return false;
}