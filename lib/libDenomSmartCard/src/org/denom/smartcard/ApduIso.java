// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard;

import org.denom.*;

import static org.denom.Binary.Bin;
import static org.denom.Ex.*;

// -----------------------------------------------------------------------------------------------------------------
/**
 * Формирование CApdu для некоторых команд ISO 7816-4.
 */
public class ApduIso
{
	// -----------------------------------------------------------------------------------------------------------------
	public static CApdu SelectFile( String fileID )
	{
		return SelectFile( Bin(fileID), SelectAnswer.FCP, CApdu.MAX_NE );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static CApdu SelectFile( final Binary fileID )
	{
		return SelectFile( fileID, SelectAnswer.FCP, CApdu.MAX_NE );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выбрать файл по File ID.
	 * @param selectAnswer - Что возвращать в ответе, см. константы в {@link SelectAnswer}.
	 */
	public static CApdu SelectFile( final Binary fileID, int selectAnswer, int Ne )
	{
		CApdu ap = new CApdu( 0x00, 0xA4, 0x00, selectAnswer, fileID, Ne, "{ISO} SELECT by FileID" );
		ap.isTlvData = true;
		return ap;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сужение интерфейса для удобства.
	 * Выбрать приложение или каталог по AID (Application Identifier).
	 * Ожидаемый ответ карты - FCI.
	 * @param aid - DF name / Applet AID.
	 */
	public static CApdu SelectAID( final Binary aid )
	{
		return SelectAID( aid, SelectAnswer.FCI, false, CApdu.MAX_NE );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static CApdu SelectAID( String aid )
	{
		return SelectAID( Bin( aid ), SelectAnswer.FCI, false, CApdu.MAX_NE );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static CApdu SelectAID( final Binary aid, int logicalChannel )
	{
		CApdu ap = SelectAID( aid );
		ap.cla = addChannelToCLA( ap.cla, logicalChannel );
		return ap;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static CApdu SelectAID( final String aid, int logicalChannel )
	{
		CApdu ap = SelectAID( aid );
		ap.cla = addChannelToCLA( ap.cla, logicalChannel );
		return ap;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выбрать приложение или каталог по AID (Application Identifier).
	 * @param aid - DF name / Applet AID, может быть задан частично,
	 * если карта поддерживает выбор по частичному AID.
	 * @param select_answer - Что возвращать в ответе, см. константы в {@link SelectAnswer}.
	 * @param next - Если false, то выбор первого, если true - выбор следующего,
	 * требуется поддержка этого режима в карте.
	 * @param len - Размер ожидаемого ответа.
	 */
	public static CApdu SelectAID( final Binary aid, int select_answer, boolean next, int len )
	{
		int p2 = select_answer;
		if( next )
		{
			p2 = select_answer | 0x02;
		}
		CApdu ap = new CApdu( 0x00, 0xA4, 0x04, p2, aid, len, "{ISO} SELECT by AID" );
		ap.isTlvData = true;
		return ap;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static int addChannelToCLA( int cla, int channelId )
	{
		MUST( Int.isU8( channelId ) && (channelId < 20), "Wrong channelID" );
		if( channelId <= 3 )
		{
			cla |= channelId;
		}
		else
		{
			cla |= (0x40 | (channelId - 4));
		}

		return cla;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Открыть логический канал.
	 * @param curChannel номер канала, на котором передавать CApdu (передаём в CLA)
	 * @param newChannel [0..19]. Если задан 0 - то карта назначит номер канала и вернёт один байт с номером открытого канала.
	 */
	public static CApdu ManageChannelOpen( int curChannel, int newChannel )
	{
		int cla = addChannelToCLA( 0x00, curChannel );
		int Ne = (newChannel == 0) ? 1 : 0;
		CApdu ap = new CApdu( cla, 0x70, 0x00, newChannel, Bin(), Ne, "{ISO} MANAGE CHANNEL (open)" );
		return ap;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Закрыть логический канал.
	 * @param curChannel номер канала, на котором передавать CApdu (передаём в CLA)
	 * @param сhannelToClose [1..19].
	 * @return
	 */
	public static CApdu ManageChannelClose( int curChannel, int сhannelToClose )
	{
		int cla = addChannelToCLA( 0x00, curChannel );
		CApdu ap = new CApdu( cla, 0x70, 0x80, сhannelToClose, Bin(), 0, "{ISO} MANAGE CHANNEL (close)" );
		return ap;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Считать запись из файла записей.
	 * @param record_number - Номер записи, от 1 до 255.
	 * @param short_id - Короткий идентификатор файла, 0 = текущий файл.
	 */
	public static CApdu ReadRecord( int short_id, int record_number )
	{
		MUST( (short_id >= 0) && (short_id < 31), "Wrong 'Short File ID'" );
		MUST( (record_number > 0) && (record_number <= 255), "Wrong 'Record number'" );
		
		CApdu ap = new CApdu( 0x00, 0xB2, record_number, (short_id << 3) | 0x04, Bin(), CApdu.MAX_NE, "{ISO} READ RECORD" );
		ap.isTlvData = true;
		return ap;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Изменить содержимое записи в файле записей.
	 * @param record_number - Номер записи, от 1 до 255.
	 * @param record - Содержимое записи.
	 * @param short_id - Короткий идентификатор файла, 0 = текущий файл.
	 */
	public static CApdu UpdateRecord( int short_id, int record_number, final Binary record )
	{
		MUST( (record_number > 0) && (record_number <= 255), "Wrong 'Record number'" );
		MUST( (short_id >= 0) && (short_id < 31), "Wrong 'Short File ID'" );

		CApdu ap = new CApdu( 0x00, 0xDC, record_number, (short_id << 3) | 0x04, record, 0, "{ISO} UPDATE RECORD" );
		ap.isTlvData = true;
		return ap;
	}

	// =================================================================================================================

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Команда GET DATA с чётным INS (0xCA).<br>
	 * Считать данные из TF / контекста DF / глобальные данные карты, доступные для чтения этой командой.
	 * @param ber_tag - 1- или 2-х-байтовый тег.
	 * @param len - Размер ожидаемого ответа.
	 */
	public static CApdu GetData( int ber_tag, int len )
	{
		MUST( Int.isU16( ber_tag ), "Wrong BER Tag" );
		return new CApdu( 0x00, 0xCA, ber_tag >>> 8, ber_tag & 0xFF, Bin(), len, "{ISO} GET DATA" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Команда PUT DATA с чётным INS (0xCA).<br>
	 * Записать данные в TF / контекст DF / глобальные данные карты, доступные для записи этой командой.
	 * @param ber_tag - 1- или 2-х-байтовый тег.
	 * @param value - Данные.
	 */
	public static CApdu PutData( int ber_tag, final Binary value )
	{
		MUST( Int.isU16( ber_tag ), "Wrong BER Tag" );
		return new CApdu( 0x00, 0xDA, ber_tag >>> 8, ber_tag & 0xFF, value, 0, "{ISO} PUT DATA" );
	}

	// =================================================================================================================
	/**
	 * Получить случайное число карты.
	 * @param len - Размер ожидаемого ответа.
	 */
	public static CApdu GetChallenge( int len )
	{
		return new CApdu( 0x00, 0x84, 0x00, 0x00, Bin(), len, "{ISO} GET CHALLENGE" );
	}
}
