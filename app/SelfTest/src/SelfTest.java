
import java.util.*;

import org.denom.*;
import org.denom.log.*;
import org.denom.d5.*;

//import static org.denom.Binary.Bin;
//import static org.denom.Ex.MUST;

// -----------------------------------------------------------------------------------------------------------------
public class SelfTest
{
	static ILog log = new LogConsole();

	public static void main( String[] args )
	{
		D5Client client = new D5Client( "denom.org", 4210 );

		Ticker ticker = new Ticker();
		
		for( int i = 0; i < 10; ++i )
		{
			client.commandEnumCommands();
		}

		log.writeln( "" + ticker.getDiffMs() );

		Collection<Integer> cmds = client.commandEnumCommands();
		for( int cmd : cmds )
			log.writeln( String.format( "%8X", cmd ) );

		client.close();
	}
}



//columnName.setCellFactory( param ->
//{
//	return new TableCell<RelayContact, String>()
//	{
//		@Override
//		protected void updateItem( String item, boolean empty )
//		{
//			super.updateItem( item, empty );
//			super.setGraphic( null );
//			super.setText( null );
//
//			if( item == null )
//				return;
//				
//			RelayContact contact = getTableRow().getItem();
//			super.setText( contact.getName() );
//		}
//	};
//} );


//columnName.setCellValueFactory( (cdf) -> 
//{
//	return new ObservableValueBase<String>()
//	{
//		@Override
//		public String getValue()
//		{
//			return new Binary().random( 10 ).Hex();
//			//return cdf.getValue().getName() + " 21323 23 ";
//		}
//	};
//} );