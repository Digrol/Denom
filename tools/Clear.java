import java.util.*;
import java.io.*;
import java.nio.file.*;

public class Clear
{
	public static void main( String[] args ) throws Exception
	{
		// Clearing all 'trunk' from common java trash
		Files.walk( Paths.get( ".." ) ).forEach( file ->
		{
			String fileName = file.getFileName().toString();
			switch( fileName )
			{	
				case ".bin":
				case "jrun.log":
					delete( file );
			}
				
			if( fileName.endsWith(".iml") )
				delete( file );
		} );

		System.out.println( "Cleared" );
	}	


	// Delete file or directory with all sub dirs and files
	static void delete( Path file )
	{
		try
		{
			if( Files.isDirectory( file ) ) 
				Files.walk( file ).sorted( Comparator.reverseOrder() ).map( Path::toFile ).forEach( File::delete );
			else
				Files.delete( file );
		}
		catch( Throwable ex ) { System.out.println( ex ); }
	}
}
