#pragma once

#ifdef WIN32
#	include <stdio.h>
#	include <stdarg.h>

#define	LOG_EMERG	0	/* system is unusable */
#define	LOG_ALERT	1	/* action must be taken immediately */
#define	LOG_CRIT	2	/* critical conditions */
#define	LOG_ERR		3	/* error conditions */
#define	LOG_WARNING	4	/* warning conditions */
#define	LOG_NOTICE	5	/* normal but significant condition */
#define	LOG_INFO	6	/* informational */
#define	LOG_DEBUG	7	/* debug-level messages */

inline void syslog( int priority, const char *format, ... )
{
	va_list args;
	va_start( args, format );
	switch( priority )
	{
	case LOG_EMERG:
	case LOG_ALERT:
	case LOG_CRIT:
	case LOG_ERR:
		fputs( "[Error] ", stderr );
		vfprintf( stderr, format, args );
		break;
	case LOG_WARNING:
		fputs( "[Warning] ", stderr );
		vfprintf( stderr, format, args );
		break;
	default:
		fputs( "[Info] ", stdout );
		vfprintf( stdout, format, args );
		break;
	}
	
	va_end( args );
}

inline void openlog( const char *ident, int option, int facility )
{

}

inline void closelog( void )
{

}
#else
#	include <syslog.h>
#endif