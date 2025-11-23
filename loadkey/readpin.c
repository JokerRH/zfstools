#include <termios.h>
#include <stdio.h>
#include <unistd.h>

unsigned YK_ReadPIN( char pin[ 8 ] )
{
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
}