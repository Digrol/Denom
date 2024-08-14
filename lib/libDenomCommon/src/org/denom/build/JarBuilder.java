// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.build;

import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.zip.*;

import org.denom.*;
import org.denom.log.*;

import static org.denom.Ex.*;

/**
 * Building JAR-files.
 * Example:
 *
 * JarBuilder jb = new JarBuilder( new LogConsole(), "program.jar" );
 * jb.exclude( "NotForAndroid.java" );
 * jb.addDirectory( "ExampleProject/.bin" );
 * jb.addZip( "/lib/somelib.jar" );
 * jb.addManifest( Main.class );
 * jb.close();
 */
public class JarBuilder implements AutoCloseable
{
	private final ILog log;
	private ZipOutputStream outputJar;

	/**
	 * List of names (dirs and files) to exclude from JAR.
	 */
	private Arr<String> excludeList = new Arr<String>();

	// -----------------------------------------------------------------------------------------------------------------
	public JarBuilder( ILog log, String outputJarPath )
	{
		this.log = log;

		try
		{
			log.writeln( "Creating JAR '" + outputJarPath + "'..." );
			outputJar = new ZipOutputStream( new FileOutputStream( outputJarPath ) );
		}
		catch( FileNotFoundException ex )
		{
			THROW( ex.toString() );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public void close()
	{
		try
		{
			outputJar.close();
			log.writeln( "JAR created" );
		}
		catch( IOException ex )
		{
			THROW( ex.toString() );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Do not include this file or dir when creating JAR.
	 */
	public void exclude( String fileName )
	{
		excludeList.add( fileName.toLowerCase() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void exclude( String[] fileNames )
	{
		for( String fileName : fileNames )
			excludeList.add( fileName.toLowerCase() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Add content of directory 'inputDirPath'.
	 */
	public void addDirectory( String inputDirPath )
	{
		log.write( "  + Directory '" + inputDirPath + "' ... " );
		addDirToZip( outputJar, inputDirPath, excludeList );
		log.writeln( "OK" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Add content of another zip or jar-file.
	 */
	public void addZip( String inputZipPath )
	{
		log.write( "  + Zip '" + inputZipPath + "' ... " );
		addZipToZip( outputJar, inputZipPath, excludeList );
		log.writeln( "OK" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void addManifest( String manifestStrings )
	{
		if( (manifestStrings == null) || manifestStrings.isEmpty() )
			return;

		log.write( "  + Manifest ... " );

		try
		{
			outputJar.putNextEntry( new ZipEntry( "META-INF/MANIFEST.MF" ) );

			String manifest = "Manifest-Version: 1.0\n" + manifestStrings + "\n";
			outputJar.write( manifest.getBytes() );
		}
		catch( Throwable ex )
		{
			THROW( ex );
		}

		log.writeln( "OK" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Add manifest for main class.
	 */
	public void addManifest( Class<?> mainClass )
	{
		addManifest( "Main-Class: " + mainClass.getCanonicalName() );
	}

	// =================================================================================================================
	private static boolean isExcluded( String fileName, final Collection<String> excludeList )
	{
		if( (excludeList == null) || excludeList.isEmpty() )
			return false;

		// Exclude nested classes
		if( fileName.endsWith( ".class" ) )
		{
			int firstIndex = fileName.indexOf( '$' );
			if( firstIndex != -1 )
			{
				fileName = fileName.substring( 0, firstIndex ) + ".class";
			}
		}

		for( String excludeName : excludeList )
		{
			if( fileName.toLowerCase().endsWith( excludeName ) )
				return true;
		}
		return false;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Add Zip-file content to Zip-stream.
	 */
	public static void addZipToZip( ZipOutputStream outputZip, String inputZip, final Collection<String> excludeList )
	{
		byte[] buf = new byte[ 8192 ];

		try( ZipFile zip = new ZipFile( inputZip ) )
		{
			Enumeration<? extends ZipEntry> entries = zip.entries();
			while( entries.hasMoreElements() )
			{
				ZipEntry entry = entries.nextElement();

				if( isExcluded( entry.getName(), excludeList ) )
					continue;

				outputZip.putNextEntry( new ZipEntry( entry.getName() ) );

				InputStream in = zip.getInputStream( entry );
				int len;
				while( (len = in.read( buf )) > 0 )
				{
					outputZip.write( buf, 0, len );
				}
			}
		}
		catch( IOException ex )
		{
			THROW( ex );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Add Directory content to Zip-stream.
	 */
	public static void addDirToZip( ZipOutputStream outputZip, String inputDirPath, final Collection<String> excludeList )
	{
		Path dirPath = Paths.get( inputDirPath );
		MUST( Files.isDirectory( dirPath ) );

		int baseFoldersCount = dirPath.getNameCount();

		try
		{
			Files.walkFileTree( dirPath, new FileVisitor<Path>()
			{
				public FileVisitResult visitFile( Path file, BasicFileAttributes attrs )
				{
					// Related path to file in zip.
					String entryPath = file.subpath( baseFoldersCount, file.getNameCount() ).toString();
					String entryName = entryPath.replace( '\\', '/' );
	
					if( isExcluded( entryName, excludeList ) )
						return FileVisitResult.CONTINUE;
	
					try
					{
						outputZip.putNextEntry( new ZipEntry( entryName ) );
						Files.copy( file, outputZip );
					}
					catch( IOException e )
					{
						THROW( e );
					}
					return FileVisitResult.CONTINUE;
				}
	
				public FileVisitResult preVisitDirectory( Path dir, BasicFileAttributes attrs )
				{
					if( isExcluded( dir.toString().replace( '\\', '/' ), excludeList ) )
						return FileVisitResult.SKIP_SUBTREE;
					return FileVisitResult.CONTINUE;
				}
	
				public FileVisitResult visitFileFailed( Path file, IOException ex )
				{
					return FileVisitResult.CONTINUE;
				}
	
				public FileVisitResult postVisitDirectory( Path dir, IOException ex )
				{
					return FileVisitResult.CONTINUE;
				}
			} );
		}
		catch( Throwable ex )
		{
			THROW( ex );
		}
	}
}
