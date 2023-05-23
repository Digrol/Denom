// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.sharim;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;

import org.denom.*;
import org.denom.format.*;

public class SharimFileInfo implements IBinable
{
	/**
	 * Max part size that can be downloaded in one request.
	 */
	public static final long MAX_FILE_PART_SIZE = 100 * 1024;

	public String name;
	public boolean isDirectory;
	public long size = 0;
	public long timeModified = 0;
	public Binary hash = new Binary();

	// -----------------------------------------------------------------------------------------------------------------
	public SharimFileInfo() {}

	// -----------------------------------------------------------------------------------------------------------------
	public SharimFileInfo( Path file )
	{
		try
		{
			name = file.getFileName().toString();

			BasicFileAttributes attr = Files.readAttributes( file, BasicFileAttributes.class );

			isDirectory = attr.isDirectory();

			if( attr.isRegularFile() )
			{
				size = attr.size();
				timeModified = attr.lastModifiedTime().toMillis();
			}
		}
		catch( IOException ex ){ throw new Ex( ex.toString() ); }
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public Binary toBin()
	{
		BinBuilder bb = new BinBuilder();
		bb.append( name );
		bb.append( isDirectory );
		bb.append( size );
		bb.append( timeModified );
		bb.append( hash );
		return bb.getResult();
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public SharimFileInfo fromBin( Binary bin, int offset )
	{
		BinParser bp = new BinParser( bin, offset );
		name = bp.getString();
		isDirectory = bp.getBoolean();
		size = bp.getLong();
		timeModified = bp.getLong();
		hash = bp.getBinary();
		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public String toString()
	{
		StringBuilder sb = new StringBuilder(40);
		sb.append( name );
		if( isDirectory )
		{
			sb.append( " (dir)" );
		}
		else
		{
			sb.append( " -- " );
			sb.append( size );
			if( !hash.empty() )
			{
				sb.append( ", hash: " );
				sb.append( hash.Hex( 0 ) );
			}
		}

		return sb.toString();
	}
}