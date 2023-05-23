// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.sharim;

import java.io.*;
import java.nio.file.*;

import org.denom.*;
import org.denom.format.*;
import org.denom.d5.relay.*;

import static org.denom.Ex.*;

// -----------------------------------------------------------------------------------------------------------------
public class SharimRelayResource extends RelayResourceClient
{
	private SharedDirs shares = new SharedDirs();

	// -----------------------------------------------------------------------------------------------------------------
	public SharimRelayResource( RelaySigner resourceKey, String name, String description )
	{
		super( resourceKey, name, description, 4, "SharimResource" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void setShares( SharedDirs sharedDirs )
	{
		this.shares = sharedDirs;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вызывается в одном из рабочих потоков.
	 */
	@Override
	protected Binary dispatchSend( long userHandle, int userToResourceIndex, int commandCode, Binary data )
	{
		Binary answerData = null;
		BinParser parser = new BinParser( data );
		switch( commandCode )
		{
			case SharimCommand.GET_SHARES_LIST: answerData = onGetSharesList( userHandle, parser ); break;
			case SharimCommand.LIST_FILES:      answerData = onListFiles( userHandle, parser ); break;
			case SharimCommand.GET_FILE_INFO:   answerData = onGetFileInfo( userHandle, parser ); break;
			case SharimCommand.GET_FILE_PART:   answerData = onGetFilePart( userHandle, parser ); break;
			default:
				THROW( "Command code not supported" );
		}

		return answerData;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private Binary onGetSharesList( long userHandle, BinParser parser )
	{
		Binary userPublicKey = userSMSesions.get( userHandle ).otherStaticPublic;

		Arr< Pair<String, Boolean> > shareList = shares.getSharesListForUser( userPublicKey );
		BinBuilder bb = new BinBuilder();
		bb.append( shareList.size() );
		for( int i = 0; i < shareList.size(); ++i )
		{
			bb.append( shareList.get( i ).key );
			bb.append( shareList.get( i ).value );
		}
		return bb.getResult();
	}

	// -----------------------------------------------------------------------------------------------------------------
	private Binary onListFiles( long userHandle, BinParser parser )
	{
		Binary userPublicKey = userSMSesions.get( userHandle ).otherStaticPublic;

		String shareName = parser.getString();
		String relativeDirPath = parser.getString();

		SharedDir sharedDir = shares.getShare( shareName );
		MUST( sharedDir != null, "Wrong Share Name" );
		MUST( sharedDir.haveReadAccess( userPublicKey ), "Access Denied" );
		String basePath = sharedDir.path;

		Path path = Paths.get( basePath, relativeDirPath ).normalize();
		MUST( path.startsWith( basePath ), "Wrong relative Path" );
		MUST( Files.exists( path ) && Files.isDirectory( path ), "No such directory" );

		Arr<SharimFileInfo> fileInfos = new Arr<>();

		try
		{
			Files.list( path ).forEach( ( file ) ->
			{
				try
				{
					SharimFileInfo info = new SharimFileInfo( file );
					fileInfos.add( info );
				}
				catch( Throwable ex ){}
			} );
		}
		catch( IOException e )
		{
			THROW( "Can't list files" );
		}

		BinBuilder bb = new BinBuilder();
		bb.append( fileInfos );
		return bb.getResult();
	}

	// -----------------------------------------------------------------------------------------------------------------
	private Binary onGetFileInfo( long userHandle, BinParser parser )
	{
		Binary userPublicKey = userSMSesions.get( userHandle ).otherStaticPublic;

		String shareName = parser.getString();
		String relativeFilename = parser.getString();

		SharedDir sharedDir = shares.getShare( shareName );
		MUST( sharedDir != null, "Wrong Share Name" );
		MUST( sharedDir.haveReadAccess( userPublicKey ), "Access Denied" );
		String basePath = sharedDir.path;

		Path path = Paths.get( basePath, relativeFilename ).normalize();
		MUST( path.startsWith( basePath ), "Wrong relative Path" );
		MUST( Files.exists( path ), "No such file" );

		SharimFileInfo fileInfo = new SharimFileInfo( path );

		BinBuilder bb = new BinBuilder();
		bb.append( fileInfo );
		return bb.getResult();
	}

	// -----------------------------------------------------------------------------------------------------------------
	private Binary onGetFilePart( long userHandle, BinParser parser )
	{
		Binary userPublicKey = userSMSesions.get( userHandle ).otherStaticPublic;

		String shareName = parser.getString();
		String relativeFilename = parser.getString();
		long fileOffset = parser.getLong();
		long filePartSize = parser.getLong();

		SharedDir sharedDir = shares.getShare( shareName );
		MUST( sharedDir != null, "Wrong Share Name" );
		MUST( sharedDir.haveReadAccess( userPublicKey ), "Access Denied" );
		String basePath = sharedDir.path;

		Path path = Paths.get( basePath, relativeFilename ).normalize();
		MUST( path.startsWith( basePath ), "Wrong relative Path" );
		MUST( Files.exists( path ), "No such file" );

		SharimFileInfo fileInfo = new SharimFileInfo( path );
		MUST( !fileInfo.isDirectory, "FileName is directory" );

		MUST( (fileOffset >= 0) && (fileOffset < fileInfo.size), "Wrong fileOffset" );
		MUST( (filePartSize > 0) && ((fileOffset + filePartSize) <= fileInfo.size), "Wrong filePartSize" );
		MUST( filePartSize <= SharimFileInfo.MAX_FILE_PART_SIZE, "Too large filePartSize" );

		Binary filePart = new Binary( (int)filePartSize );
		try( RandomAccessFile file = new RandomAccessFile( new File( path.toString() ), "r" ) )
		{
			file.seek( fileOffset );
			file.read( filePart.getDataRef(), 0, (int)filePartSize );
		}
		catch( IOException e )
		{
			THROW( "Can't read file" );
		}

		BinBuilder bb = new BinBuilder();
		bb.append( filePart );
		return bb.getResult();
	}
}
