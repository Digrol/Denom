// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard;

import java.util.Arrays;
import java.util.Locale;

import org.denom.*;
import org.denom.log.*;

import static org.denom.Binary.*;
import static org.denom.Ex.*;

/**
 * Ответное APDU карты. ISO 7816-3, p. 12.1.1.
 */
public class RApdu
{
	/**
	 * Специальные ожидаемые статусы.
	 */
	public static final int ST_OK  = 1; // любой неошибочный статус
	public static final int ST_ERR = 2; // любой ошибочный статус
	public static final int ST_ANY = 3; // любой статус

	/**
	 * Данные ответа карты.
	 */
	public Binary response = Bin();

	/**
	 * Статус выполнения команды (2 байта).
	 */
	public int status;

	// -----------------------------------------------------------------------------------------------------------------
	public RApdu() {}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Конструктор. Поле ответа пустое и задан status.
	 */
	public RApdu( int status )
	{
		MUST( Int.isU16( status ), "Wrong status" );
		this.status = status;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Конструктор. Поле ответа и status.
	 */
	public RApdu( final Binary response, int status )
	{
		this( status );
		this.response = response.clone();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Конструктор из байтового массива по стандарту ISO 7816-3.
	 * @param bin - конкатенация: [Response] | SW1 | SW2.
	 */
	public RApdu( final Binary bin )
	{
		assign( bin );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Конструктор из байтового массива по стандарту ISO 7816-3.
	 * @param bin - конкатенация: [Response] | SW1 | SW2.
	 */
	public RApdu( final byte[] bin )
	{
		assign( bin );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Создать копию объекта.
	 */
	public RApdu clone()
	{
		return new RApdu( response, status );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return Первый байт статуса.
	 */
	public int sw1()
	{
		return (status >> 8) & 0xFF;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return Второй байт статуса.
	 */
	public int sw2()
	{
		return status & 0xFF;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Очистить все поля.
	 */
	public void clear()
	{
		status = 0;
		response = Bin();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать поля объекта согласно массиву.
	 * @param rapdu Response APDU (ISO 7816-3, п. 12.1.1)
	 */
	public void assign( final byte[] rapdu )
	{
		int sz = rapdu.length;
		MUST( sz >= 2, "Wrong len of Response APDU ( < 2 bytes)" );
		status = ((rapdu[ sz - 2 ] & 0xFF) << 8) | (rapdu[ sz - 1 ] & 0xFF);
		response.assign( rapdu, 0, sz - 2 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать поля объекта согласно массиву.
	 * @param rapdu Response APDU (ISO 7816-3, п. 12.1.1)
	 */
	public void assign( final Binary rapdu )
	{
		int sz = rapdu.size();
		MUST( sz >= 2, "Wrong len of Response APDU ( < 2 bytes)" );
		status = rapdu.getU16( sz - 2 );
		response.assign( rapdu, 0, sz - 2 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Преобразовать в массив Binary.
	 * @return байтовое представление RApdu.
	 */
	public Binary toBin()
	{
		return new Binary( response ).addU16( status );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Напечатать RApdu в лог.
	 * @param lineShift - Смещение каждой строки.
	 * @param isTlvData - Данные ожидаются в формате BER-TLV.
	 */
	public void print( ILog log, int color, int lineShift, boolean isTlvData )
	{
		if( log instanceof LogDummy )
		{
			return;
		}

		String shiftStr = "";
		if( lineShift > 0 )
		{
			char[] arr = new char[ lineShift ];
			Arrays.fill( arr, ' ' );
			shiftStr = new String( arr );
		}

		if( !response.empty() )
		{
			String response_hex = response.Hex( 1, 8, 32, lineShift );
			log.writeln( color, String.format(  Locale.US, "%1$sResponse: %2$d (0x%2$X)", shiftStr, response.size() ) );
			log.writeln( color, response_hex );

			if( isTlvData )
				CApdu.printFieldAsTLV( response, log, color, lineShift, shiftStr );
		}

		log.writeln( color, String.format( "%sStatus: %4X (%s)", shiftStr, status, getStatusDescripton( status ) ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Получить текстовое описание статуса выполнения команды.
	 * @param status - Двухбайтовый статус
	 * @return Текстовое описание статуса
	 */
	public static String getStatusDescripton( int status )
	{
		int sw1 = (status >> 8) & 0xFF;
		int sw2 = status & 0xFF;

		if( ((sw1 & 0xF0) != 0x60) && ((sw1 & 0xF0) != 0x90) )
		{
			return "Protocol error (first nibble must be '6' or '9')";
		}

		if( status == 0x9000 )
		{
			return "Ok";
		}

		// Case 4
		if( sw1 == 0x61 )
		{
			return Integer.toHexString( sw2 ) + " bytes available";
		}

		// Case 2
		if( sw1 == 0x6C )
		{
			return "Resend command with P3 = " + Integer.toHexString( sw2 );
		}

		// Счетчик попыток
		if( (status & 0xFFF0) == 0x63C0 )
		{
			return "Wrong key, attempts left: " + (sw2 & 0x0F);
		}

		if( sw1 == 0x91 )
		{
			return "Proactive command on card";
		}

		switch( status )
		{
			case 0x9300: return "SIM Application Toolkit is busy";

			case 0x6200: return "Warning: State of non-volatile memory is unchanged";
			case 0x6281: return "Warning: Part of returned data may be corrupted";
			case 0x6282: return "Warning: End of file or record reached before reading Ne bytes";
			case 0x6283: return "Warning: Selected file deactivated";
			case 0x6284: return "Warning: File control information not formatted according to 5.3.3";
			case 0x6285: return "Warning: Selected file in termination state";
			case 0x6286: return "Warning: No input data available from a sensor on the card";

			case 0x6300: return "State of non-volatile memory has changed";
			case 0x6381: return "File filled up by the last write";

			case 0x6400: return "State of non-volatile memory is unchanged";
			case 0x6401: return "Immediate response required by the card";

			case 0x6500: return "State of non-volatile memory has changed";
			case 0x6581: return "Memory failure";

			case 0x6600: return "Security-related issues";

			case 0x6700: return "Wrong length";

			case 0x6800: return "Functions in CLA not supported";
			case 0x6881: return "Logical channel not supported";
			case 0x6882: return "Secure messaging not supported";
			case 0x6883: return "Last command of the chain expected";
			case 0x6884: return "Command chaining not supported";

			case 0x6900: return "Command not allowed";
			case 0x6981: return "Command incompatible with file structure";
			case 0x6982: return "Security status not satisfied";
			case 0x6983: return "Authentication method blocked";
			case 0x6984: return "Reference data not usable";
			case 0x6985: return "Conditions of use not satisfied";
			case 0x6986: return "Command not allowed (no current EF)";
			case 0x6987: return "Expected secure messaging data objects missing";
			case 0x6988: return "Incorrect secure messaging data objects";

			case 0x6A00: return "Wrong parameters P1-P2";
			case 0x6A80: return "Incorrect parameters in the command data field";
			case 0x6A81: return "Function not supported";
			case 0x6A82: return "File or application not found";
			case 0x6A83: return "Record not found";
			case 0x6A84: return "Not enough memory space in the file";
			case 0x6A85: return "Nc inconsistent with TLV structure";
			case 0x6A86: return "Incorrect parameters P1-P2";
			case 0x6A87: return "Nc inconsistent with parameters P1-P2";
			case 0x6A88: return "Referenced data or reference data not found";
			case 0x6A89: return "File already exists";
			case 0x6A8A: return "DF name already exists";

			case 0x6B00: return "Wrong parameters P1-P2";
			case 0x6C00: return "Wrong Le field; SW2 encodes the exact number of available data bytes";
			case 0x6D00: return "Instruction code not supported or invalid ";
			case 0x6E00: return "Class not supported";
			case 0x6F00: return "No precise diagnosis";
		}
		return "Unknown Error";
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Проверить, является ли статус выполнения команды успешным.
	 */
	public boolean isOk()
	{
		return (status == 0x9000) || (sw1() == 0x61) || (sw1() == 0x91);
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Проверить, совпал ли ожидаемый статус с полученным.
	 * @param expectedStatus - Ожидаемый статус.
	 * @param callClassName - Имя класса вызвавшего команду (для стека в сообщении об ошибке).
	 */
	public void checkStatus( int expectedStatus, String callClassName )
	{
		if( !isExpectedStatus( expectedStatus ) )
		{
			throw new Ex( formUnexpectedMsg( expectedStatus ), Ex.getCallerPlace( callClassName ) );
		}
	}

	// ---------------------------------------------------------------------------------------------------------------------
	/**
	 * Проверить, совпал ли ожидаемый статус с полученным.
	 * @param expectedStatus - Ожидаемый статус.
	 */
	private boolean isExpectedStatus( int expectedStatus )
	{
		switch( expectedStatus )
		{
			case ST_OK:  return isOk();
			case ST_ERR: return !isOk();
			case ST_ANY: return true;
			default:     return expectedStatus == status;
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Формирует сообщение о том, что карта вернула неожиданный статус.
	 * @param expectedStatus - Ожидаемый статус.
	 */
	private String formUnexpectedMsg( int expectedStatus )
	{
		StringBuilder err = new StringBuilder( 100 );
		err.append( "Wrong status. Expected: " );
		
		switch( expectedStatus )
		{
			case ST_OK:  err.append( "OK" );  break;
			case ST_ERR: err.append( "ERR" ); break;
			case ST_ANY: err.append( "ANY" ); break;
			default:     err.append( Binary.Num_Bin( expectedStatus, 2 ).Hex() );
		}

		err.append( ", card status: " );
		err.append( Binary.Num_Bin( status, 2 ).Hex() );

		return err.toString();
	}

}
