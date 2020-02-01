// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom;

import java.util.*;
import java.util.stream.Stream;
import java.io.File;
import java.io.IOException;
import java.nio.file.*;

import org.denom.log.ILog;

import static org.denom.Ex.*;

/**
 * Системно-зависимые утилиты. Работа с файлами и процессами.
 */
public final class Sys
{
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Приостановить выполнение текущего потока на {@code ms} миллисекунд.
	 */
	public static void sleep( long ms )
	{
		try
		{
			Thread.sleep( ms );
		}
		catch( InterruptedException ex )
		{
			throw new Ex( ex.toString(), ex );
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
			return Runtime.getRuntime().exec( cmdLine ).waitFor();
		}
		catch( Throwable ex )
		{
			THROW( ex );
		}
		return 0;
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

}
