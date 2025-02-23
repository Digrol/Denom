// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv.kernel8.struct;

import org.denom.Binary;

import static org.denom.Binary.Bin;
import static org.denom.format.BerTLV.Tlv;

/**
 * Результат работы ядра - это сигнал OUT.
 * Book C-8, 2.2.4, Table 2.4 - Responses from Process K.
 * Параметры сигнала - это 2 обязательных и 3 опциональных объекта данных (TLV):
 * всегда передаются TLV 'Outcome Parameter Set' и TLV 'Discretionary Data'.
 * Опционально - 'Data Record', 'User Interface Request Data 1', 'User Interface Request Data 1'.
 */
public class OUT extends RuntimeException
{
	private static final long serialVersionUID = 1L;

	public final Binary outData;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Конкатенация всех TLV-объектов, которые нужно передать в сигнале OUT.
	 */
	public OUT( Binary outData )
	{
		this.outData = outData;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param outcomeParameterSet - [8 байт] - поле value для TLV Outcome Parameter Set (tag 9F8210).
	 */
	public OUT( TlvDatabase tlvDB, Binary outcomeParameterSet, boolean createDataRecord, UIRD uird1, UIRD uird2 )
	{
		Binary b = Bin();

		b.add( tlvDB.createDiscretionaryData() );

		if( createDataRecord )
			b.add( tlvDB.createDataRecord() );

		if( uird1 != null )
			b.add( Tlv( TagKernel8.UserInterfaceRequestData1, uird1.toBin() ) );

		if( uird2 != null )
			b.add( Tlv( TagKernel8.UserInterfaceRequestData2, uird2.toBin() ) );

		this.outData = b;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * UIRD2 задаётся редко.
	 */
	public OUT( TlvDatabase tlvDB, Binary outcomeParameterSet, boolean createDataRecord, UIRD uird1 )
	{
		this( tlvDB, outcomeParameterSet, createDataRecord, uird1, null );
	}

}
