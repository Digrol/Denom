// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom;

import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import java.io.*;
import java.nio.file.*;

import org.denom.log.ILog;

import static org.denom.Ex.*;

/**
 * Some tools for work with files, threads, processes.
 */
public final class Sys
{
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Causes the currently executing thread to sleep for the specified number of milliseconds.
	 * @throws Ex when current thread interrupted. The thread's interrupt status will be set,
	 * i.e. Thread.currentThread().isInterrupted() == true.
	 */
	public static void sleep( long ms )
	{
		try
		{
			Thread.sleep( ms );
		}
		catch( InterruptedException ex )
		{
			Thread.currentThread().interrupt();
			throw new Ex( "Sleep interrupted" );
		}
	}

	//------------------------------------------------------------------------------------------------------------------
	/**
	 * Shutdown Executor and wait some seconds until it stoped.
	 * Throws exception if can't shutdown or thread interrupted.
	 */
	public static void shutdownNow( ExecutorService executor, int waitSeconds )
	{
		executor.shutdownNow();
		try
		{
			if( !executor.awaitTermination( waitSeconds, TimeUnit.SECONDS ) )
				throw new Ex( "Can't stop executor " + executor.toString() );
		}
		catch( InterruptedException ex )
		{
			Thread.currentThread().interrupt();
			throw new Ex( "Executor shutdownNow() interrupted!" );
		}
	}
	
	
	//------------------------------------------------------------------------------------------------------------------
	/**
	 * Запустить новый процесс и дождаться его завершения.
	 * Вывод процесса - игнорируется.
	 * @param cmdLine - Командная строка.
	 * @return Код, с которым завершилось запущенное приложение.
	 */
	public static int execAndWait( String cmdLine )
	{
		try
		{
			return new ProcessBuilder( cmdLine ).start().waitFor();
		}
		catch( InterruptedException e )
		{
			Thread.currentThread().interrupt();
			THROW( "Executing process with cmdLine '" + cmdLine + "' is interrupted" );
		}
		catch( Throwable ex )
		{
			THROW( ex );
		}
		return 0;
	}


	// -----------------------------------------------------------------------------------------------------------------
	public static int execAndWait( String execFile, String... cmdArgs )
	{
		List<String> args = new ArrayList<>( cmdArgs.length + 1 );
		args.add( execFile );
		for( String arg : cmdArgs )
			args.add( arg );
		return execAndWait( args );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static int execAndWait( List<String> cmdArgs )
	{
		try
		{
			ProcessBuilder processBuilder = new ProcessBuilder( cmdArgs );
			processBuilder.redirectErrorStream( true );
			processBuilder.redirectOutput( ProcessBuilder.Redirect.INHERIT );
			return processBuilder.start().waitFor();
		}
		catch( InterruptedException e )
		{
			Thread.currentThread().interrupt();
			throw new RuntimeException( "Executing process with cmdLine '" + cmdArgs + "' is interrupted" );
		}
		catch( Throwable ex )
		{
			throw new RuntimeException( ex );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Запустить дочерний процесс и дождаться его завершения.
	 * @param cmdLine - командная строка.
	 * @param outputFile - направить поток вывода процесса в этот файл.
	 * @param errorFile - направить error-поток процесса в этот файл.
	 * @return Код, с которым завершилось запущенное приложение.
	 */
	public static int execAndWait( String cmdLine, String outputFile, String errorFile )
	{
		StringTokenizer st = new StringTokenizer( cmdLine.toString() );
		String[] cmdarray = new String[ st.countTokens() ];
		for( int i = 0; st.hasMoreTokens(); i++ )
			cmdarray[ i ] = st.nextToken();

		ProcessBuilder processBuilder = new ProcessBuilder( cmdarray );
		processBuilder.redirectOutput( new File( outputFile ) );
		processBuilder.redirectError( new File( errorFile ) );
		Process p;
		try
		{
			p = processBuilder.start();
			return p.waitFor();
		}
		catch( InterruptedException e )
		{
			Thread.currentThread().interrupt();
			THROW( "Executing process with cmdLine '" + cmdLine + "' is interrupted" );
		}
		catch( Throwable ex )
		{
			THROW( "Can't execute process with cmdLine: " + cmdLine + "\n" + ex.toString() );
		}
		return -1;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Содержимое файлов-потоков вывода запускаемого процесса выводится в ILog, файлы удаляются.
	 * @return Код, с которым завершилось запущенное приложение.
	 */
	public static int execAndWait( String cmdLine, ILog log )
	{
		Path outLog = Paths.get( "output.log" );
		Path errLog = Paths.get( "error.log" );

		int res = execAndWait( cmdLine, outLog.toString(), errLog.toString() );

		try
		{
			if( Files.exists( outLog ) )
			{
				try( Stream<String> stream = Files.lines( outLog ) )
				{
					stream.forEach( line -> log.writeln( line ) );
				}
			}

			if( Files.exists( errLog ) )
			{
				try( Stream<String> stream = Files.lines( errLog ) )
				{
					stream.forEach( line -> log.writeln( line ) );
				}
			}

			Files.deleteIfExists( outLog );
			Files.deleteIfExists( errLog );
		}
		catch( IOException ex ) {}

		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Переименовать файл.
	 */
	public static void renameFile( String oldName, String newName )
	{
		try
		{
			Files.move( Paths.get( oldName ), Paths.get( newName ), StandardCopyOption.REPLACE_EXISTING );
		}
		catch( Throwable ex )
		{
			THROW( ex.toString() );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Существует ли файл.
	 */
	public static boolean isFileExist( String fileName )
	{
		return Files.exists( Paths.get( fileName ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Существует ли файл.
	 */
	public static void checkFileExist( String fileName )
	{
		MUST( Files.exists( Paths.get( fileName ) ), "File '" + fileName + "' not found" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static Path tempDirJni = null;
	/**
	 * Загрузить DLL-ку из JAR-файла.
	 * JAR, содержащий DLL, должен быть в classpath.
	 * @param path Путь к DLL-файлу внутри JAR.
	 * DLL копируется во временный каталог, который будет удалён при закрытии приложения.
	 */
	public static void loadLibraryFromJar( String path )
	{
		try
		{
			// Каталог для временных JNI-файлов.
			if( tempDirJni == null )
			{
				String tempDir = System.getProperty( "java.io.tmpdir" );
				tempDirJni = Files.createDirectories( Paths.get( tempDir, "denom_jni_temp" + System.nanoTime() ) );
				MUST( tempDirJni != null, "Can't create temp directory: " + tempDirJni.toString() );
				tempDirJni.toFile().deleteOnExit();
			}
	
			Path tempFileName = Paths.get( tempDirJni.toString(), Paths.get( path ).getFileName().toString() );
	
			try( InputStream is = ClassLoader.getSystemResourceAsStream( path ) )
			{
				Files.copy( is, tempFileName, StandardCopyOption.REPLACE_EXISTING );
			}
			catch( Throwable ex )
			{
				Files.deleteIfExists( tempFileName );
				THROW( ex.toString() );
			}
	
			try
			{
				System.load( tempFileName.toAbsolutePath().toString() );
			}
			finally
			{
				if( isPosixCompliant() )
				{	// Assume POSIX compliant file system, can be deleted after loading
					Files.deleteIfExists( tempFileName );
				}
				else
				{	// Assume non-POSIX, and don't delete until last file descriptor closed
					tempFileName.toFile().deleteOnExit();
				}
			}
		}
		catch (Throwable ex)
		{
			THROW( ex.toString() );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static boolean isPosixCompliant()
	{
		try
		{
			return FileSystems.getDefault().supportedFileAttributeViews().contains( "posix" );
		}
		catch( FileSystemNotFoundException | ProviderNotFoundException | SecurityException e )
		{
			return false;
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static void deleteFile( String fileOrDir )
	{
		deleteFile( Paths.get( fileOrDir ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	// Delete file or directory with all sub dirs and files
	public static void deleteFile( Path fileOrDir )
	{
		try
		{
			if( Files.isDirectory( fileOrDir ) ) 
				Files.walk( fileOrDir ).sorted( Comparator.reverseOrder() ).map( Path::toFile ).forEach( File::delete );
			else
				Files.deleteIfExists( fileOrDir );
		}
		catch( Throwable ex ) { throw new RuntimeException( ex ); }
	}
}
