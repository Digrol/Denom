// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.tlspsk;

import org.denom.*;
import org.denom.log.*;
import org.denom.net.SocketClient;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;
import static org.denom.tlspsk.TlsConst.*;

public abstract class TlsPSKPeer
{
	protected ILog log;
	protected final static int COLOR_SEND1 = 0xFF40A0FF;
	protected final static int COLOR_SEND2 = 0xFF36BCFF;
	protected final static int COLOR_SEND3 = 0xFF10F0FF;
	protected final static int COLOR_RECV1 = 0xFFF050F5;
	protected final static int COLOR_RECV2 = 0xFFF090F0;
	protected final static int COLOR_RECV3 = 0xFFFFC0FF;

	protected SocketClient socketClient;
	protected boolean closed = false;

	Binary recordHeader = Bin().reserve(5);
	Binary recordBody = Bin();

	private Binary bufHandshake = Bin();
	private Binary bufApplication = Bin();

	protected TlsPSKSession session;

	// -----------------------------------------------------------------------------------------------------------------
	protected TlsPSKPeer( ILog log )
	{
		this.log = log;
		session = new TlsPSKSession( log );
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected abstract void onHandshakeMessage( final Binary message, int type, final Binary data );

	protected abstract void onChangeCipher();

	// -----------------------------------------------------------------------------------------------------------------
	protected void readRecord()
	{
		try
		{
			// Read and parse HEADER
			socketClient.read( recordHeader, 5 );

			int recordType = recordHeader.get( 0 );
			int version = recordHeader.getU16( 1 );
			int length = recordHeader.getU16( 3 );
			MUST( length <= session.cryptLimit, Alert.RECORD_OVERFLOW );

			// Read RECORD BODY
			socketClient.read( recordBody, length );

			log.writeln( COLOR_RECV1, String.format( "recv [%4d] : %02X %04X %04X %s",
					recordBody.size() + 5, recordType, version, length, recordBody.Hex()) );

			// Decrypt
			recordBody = session.decodeRecord( recordType, recordBody );

			MUST( recordBody.size() <= session.plainLimit, Alert.RECORD_OVERFLOW );

			switch( recordType )
			{
				case ContentType.ALERT:
					processRecordAlert( recordBody ); break;

				case ContentType.HANDSHAKE:
					processRecordHandshake( recordBody ); break;
				
				case ContentType.APPLICATION_DATA:
					MUST( session.isHandshakeDone, Alert.UNEXPECTED_MESSAGE );
					bufApplication.add( recordBody );
					break;

				case ContentType.CHANGE_CIPHER:
					processChangeCipher( recordBody );
					break;

				default: throw new Ex( Alert.UNEXPECTED_MESSAGE );
			}
		}
		catch( Ex ex )
		{
			if( !closed && (ex.code != 0) && Int.isU8( ex.code ) )
			{
				sendFatal( ex.code );
				session = null;
				socketClient.close();
				closed = true;
			}
			throw ex;
		}
		finally
		{
			recordHeader.clear();
			recordBody.clear();
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void processChangeCipher( final Binary recBody )
	{
		log.writeln( COLOR_RECV2, "    Change Cipher Spec" );
		MUST( recBody.size() == 1, Alert.DECODE_ERROR );
		MUST( recBody.get( 0 ) == 0x01, Alert.DECODE_ERROR );
		MUST( bufHandshake.size() == 0, Alert.UNEXPECTED_MESSAGE );
		onChangeCipher();
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void processRecordAlert( final Binary recBody )
	{
		MUST( recBody.size() == 2, Alert.DECODE_ERROR );

		log.writeln( COLOR_RECV2, String.format( "ALERT:  type:  %02X,  description:  %02X (%s)",
				recBody.get( 0 ), recBody.get( 1 ), Alert.toStr( recBody.get( 1 ) ) ) );

		throw new Ex( recBody.asU16(), "Alert recieved" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void processRecordHandshake( final Binary recBody )
	{
		MUST( recBody.size() > 0, Alert.DECODE_ERROR );
		bufHandshake.add( recBody );

		// We need the first 4 bytes, they contain type and length of the message.
		while( bufHandshake.size() >= 4 )
		{
			int type = bufHandshake.get( 0 );
			int dataLen = bufHandshake.getU24( 1 );
			MUST( dataLen <= 32768, Alert.RECORD_OVERFLOW );

			int fullLen = 4 + dataLen;
			if( bufHandshake.size() < fullLen )
				break; // Wait full message

			Binary message = bufHandshake.first( fullLen );
			Binary data = message.slice( 4, message.size() - 4 );

			// Убираем из буфера обрабатываемое сообщение
			bufHandshake.assign( bufHandshake, fullLen, bufHandshake.size() - fullLen );

			log.writeln( COLOR_RECV2, String.format("    Handshake msg:  type: %02X (%s), data:  %s",
					type, HandshakeType.toStr( type ), message.last( message.size() - 4 ).Hex()) );

			onHandshakeMessage( message, type, data );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected void sendRecord( int recordType, final Binary recordData )
	{
		MUST( !closed, "Closed connection" );
		MUST( recordData.size() <= session.plainLimit );

		Binary cipheredData = session.encodeRecord( recordType, recordData );

		Binary rec = new Binary().reserve( recordData.size() + 5 + 16 );
		rec.add( recordType );
		rec.addU16( session.protocolVersion );
		rec.addU16( cipheredData.size() );
		rec.add( cipheredData );

		log.writeln( COLOR_SEND1, String.format( "send [%4d] : %02X %04X %04X %s\n",
				rec.size(), recordType, session.protocolVersion, cipheredData.size(), cipheredData.Hex() ) );

		socketClient.write( rec );
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected void sendHandshakeMsg( int msgType, final Binary body )
	{
		Binary b = new Binary().reserve( 64 );
		b.add( msgType );        // HandshakeType msg_type
		b.addU24( body.size() ); // uint24 length
		b.add( body );           // body

		log.writeln( COLOR_SEND2, String.format("    Handshake msg:  type: %02X (%s), data:  %s",
				msgType, HandshakeType.toStr( msgType ), body.Hex()) );

		session.addHandshakeMessage( b );

		sendRecord( ContentType.HANDSHAKE, b );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Считать прикладные данные. Ждёт наличия данных в канале.
	 * @return непустой массив.
	 */
	public Binary readAppData()
	{
		MUST( !closed, "Cannot read application data on closed connection" );
		MUST( session.isHandshakeDone, "Cannot read application data until handshake completed." );

		while( bufApplication.empty() ) // могут быть пустые сообщения
		{
			readRecord();
		}

		Binary res = bufApplication;
		bufApplication = new Binary();
		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected void sendFatal( int alert )
	{
		try
		{
			log.writeln( COLOR_SEND2, String.format( "FATAL ALERT:  description:  %02X (%s)",
					alert, Alert.toStr(alert ) ) );

			sendRecord( ContentType.ALERT, Bin(1, 2).add( alert ) );
		}
		catch( Throwable ee ) {}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Передать прикладные данные по TLS-соединению. Данные нарезаются на фрагменты.
	 */
	public void sendAppData( final Binary data )
	{
		MUST( session.isHandshakeDone, "Cannot write application data until handshake completed." );

		int offset = 0;
		int len = data.size();
		while( len > 0 )
		{
			MUST( !closed, "Cannot write application data on closed/failed TLS connection" );

			int partSize = Math.min( len, session.plainLimit );
			sendRecord( ContentType.APPLICATION_DATA, data.slice( offset, partSize ) );
			offset += partSize;
			len -= partSize;
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected void sendChangeCipherSpec()
	{
		log.writeln( COLOR_SEND2, "    Change Cipher Spec" );
		sendRecord( ContentType.CHANGE_CIPHER, Bin(1, 1) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public void close()
	{
		if( closed )
			return;

		try
		{
			sendRecord( ContentType.ALERT, Bin(1, 1).add( Alert.CLOSE_NOTIFY ) );
		}
		catch (Throwable ex) {}

		closeNoAlert();
	}

	// -----------------------------------------------------------------------------------------------------------------
	protected void closeNoAlert()
	{
		if( closed )
			return;

		session = null;
		socketClient.close();
		this.closed = true;
	}

}
