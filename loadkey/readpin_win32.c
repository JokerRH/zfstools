#include <Windows.h>
#include <stdio.h>

unsigned YK_ReadPIN( char pin[ 8 ] )
{
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
	while( 1 )
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
}