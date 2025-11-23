#include <stdbool.h>
#include "logging.h"

bool YK_StartPCSCD( void )
{
	syslog( LOG_INFO, "Starting of pcscd is currently not supported on windows. Please manually ensure it is running." );
	return true;
}

void YK_StopPCSCD( void )
{
	syslog( LOG_INFO, "Stopping of pcscd is currently not supported on windows." );
	return true;
}