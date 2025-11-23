#include <stdbool.h>
#include "logging.h"
#include <unistd.h>
#include <linux/prctl.h>
#include <sys/prctl.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdbool.h>

bool YK_StartPCSCD( void )
{
	const pid_t ppid = getpid( );
	
	//Fork process to start pcscd
	{
		const pid_t pid = fork( );
		if( pid < 0 )
		{
			syslog( LOG_ERR, "Failed to fork process." );
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
			syslog( LOG_ERR, "Failed to set parent-death signal." );
			_exit( EXIT_FAILURE );
		}

		//Check if parent already died
		if( getppid( ) != ppid )
			_exit( EXIT_SUCCESS );
	}

	static char *const s_aszArg[ ] = { "-x", "--force-reader-polling", NULL };
	static char *const s_aszNullEnvP[ ] = { NULL };
	(void)! execve( "/sbin/pcscd", s_aszArg, s_aszNullEnvP );

	//If we reach this point, execve failed. Print error message and exit
	syslog( LOG_ERR, "Failed to start pcscd." );
	_exit( EXIT_FAILURE );
}

void YK_StopPCSCD( void )
{
	//Read pid
	//Layout at the time of opening the stat file: "/proc/" pid "/stat" (including a terminating NULL). The pid is an integer and should not be larger than 10 digits, but the pid file may contain further characters (e.g. '\n').
	//Expected layout after reading the stat file: pid " (pcscd)" (doesn't need a terminating NULL).
	//Ensure that the buffer is large enough to encompass this, but also not so large that the /proc/pid/stat file can fully fit (in that case adjust the test for file size below)
	char ab[ 32 ] = "/proc/";
	char *const abPID = ab + sizeof( "/proc/" ) - 1;
	ssize_t numChars;
	{
		const int fd = open( "/run/pcscd/pcscd.pid", O_RDONLY | O_CLOEXEC );
		numChars = read( fd, abPID, sizeof( ab ) - ( abPID - ab ) );
		close( fd );

		if( numChars < 0 )
		{
			syslog( LOG_WARNING, "Failed to read pcscd pid." );
			return;
		}
		else if( numChars >= sizeof( ab ) - ( abPID - ab ) )
		{
			syslog( LOG_WARNING, "Failed to read pcscd pid: File content is larger than expected." );
			return;
		}
	}

	//Ensure the file contains just a number (pid)
	{
		bool fValid = false;
		for( ssize_t i = 0; i < numChars; ++i )
			if( abPID[ i ] < '0' || abPID[ i ] > '9' )
			{
				if( fValid )
				{
					numChars = i;
					break;
				}
				syslog( LOG_WARNING, "Failed to read pcscd pid: File content is not a valid pid." );
				return;
			}
			else
				fValid = true;
	}
	const pid_t pid = atoi( abPID );

	//Load the content of the /proc/pid/stat file
	memcpy( abPID + numChars, "/stat", sizeof( "/stat" ) );
	{
		const int fd = open( ab, O_RDONLY | O_CLOEXEC );
		const ssize_t numRead = read( fd, ab, sizeof( ab ) );
		close( fd );

		if( numRead != sizeof( ab ) )
		{
			syslog( LOG_WARNING, "Failed to validate pcscd pid: The corresponding stat file is too short." );
			return;
		}
	}

	//Ensure the pid matches pcscd
	if( memcmp( ab + numChars, " (pcscd)", sizeof( " (pcscd)" ) - 1 ) )
	{
		syslog( LOG_WARNING, "Failed to validate pcscd pid: The pid in the daemon pid file does not match pcscd." );
		return;
	}

	//Kill pcscd
	if( kill( pid, SIGTERM ) < 0 )
		syslog( LOG_WARNING, "Failed to terminate pcscd." );
}