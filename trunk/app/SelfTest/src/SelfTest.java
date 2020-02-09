
import org.denom.*;
import org.denom.log.*;
import org.denom.D5.D5Command;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;


// -----------------------------------------------------------------------------------------------------------------
public class SelfTest
{
	static ILog log = new LogConsole();

	public static void main( String[] args )
	{
		Binary b = Bin().reserve( 11000000 );

		Ticker t = new Ticker();
		
		Binary data = new Binary(10000000, 0x05);
		D5Command command = new D5Command();
		command.index = 2;
		command.code = D5Command.ENUM_COMMANDS;
		command.data = data;
		
		command.encode( b );
		
		D5Command command2 = new D5Command();
		command2.decode( b );
		
		MUST( command2.equals( command ) );
		log.writeln( "" + t.getDiffMs() );

		log.writeln( String.format( " \n%08X", command2.index ) );
	}
}