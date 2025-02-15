// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv;

import org.denom.Binary;
import org.denom.crypt.AlignMode;
import org.denom.crypt.CryptoMode;
import org.denom.format.JSONObject;
import org.denom.smartcard.CpsDataGroup;
import org.denom.smartcard.gp.GP_SM;

import static org.denom.Ex.*;
import static org.denom.format.BerTLV.Tlv;
import static org.denom.Binary.*;

/**
 * Utilities for '*.emvperso' files and personalization process by CPS.
 */
public final class EmvPerso
{
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Тело DG шифруется на сессионном DEK-ключе, если требуется шифрование группы данных.
	 * @return dg либо без изменений, либо зашифровано на DEK
	 */
	public static CpsDataGroup encryptDG( CpsDataGroup dg, GP_SM sm )
	{
		if( dg.needEncryption )
		{
			// Encrypt DG on session DEK
			MUST( dg.data.size() % 8 == 0, "Группа данных, шифруемая на ключе DEK, должна быть кратна 8" );
			Binary encrypted = sm.dekCipher.encrypt( dg.data, CryptoMode.ECB, AlignMode.NONE );
			dg.data.assign( encrypted );
		}
		return dg;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Заменить в строке str переменные их значениями.
	 *  вместо <<Some Name>> - BER-TLV с соответствующим тегом, Value ищем в jo, номер тега - в словаре dict;
	 *  вместо <Some Name>   - значение этого объекта (ищем в jo поле с таким ключом).
	 *  @param str - строка с переменными.
	 *  @return получившийся результат.
	 */
	public static String replaceVariables( String str, JSONObject jo, ITagDictionary dict, boolean throwIfAbsent )
	{
		if( str == "" )
			return "";

		// Замена <<Some Var>> на TLV со значением переменной
		int leftPos = 0;
		int offset = 0;
		while( (leftPos = str.indexOf( "<<", offset )) != -1 )
		{
			offset = leftPos + 2;
			int rightPos = str.indexOf( ">>", leftPos );
			if( rightPos == -1 )
				continue;

			int keyLen = rightPos - leftPos - 2;
			if( keyLen < 1 )
				continue;

			String objectName = str.substring( leftPos + 2, leftPos + 2 + keyLen );

			Binary emptyBin = Bin();
			Binary referencedValue = throwIfAbsent ? jo.getBinary( objectName ) : jo.optBinary( objectName, emptyBin );

			objectName = objectName.replace( "Contact.", "" );
			objectName = objectName.replace( "Contactless.", "" );

			TagInfo tagInfo = dict.find( objectName );
			if( tagInfo == null )
				THROW( "Tag " + objectName + " not found in dictionary" );

			int tag = tagInfo.tag;

			String newValue = Tlv( tag, referencedValue ).Hex();

			str = str.replace( str.substring( leftPos, leftPos + keyLen + 4 ), newValue );
		}

		// Замена <Some Var> на значение
		offset = 0;
		while( (leftPos = str.indexOf( '<', offset )) != -1 )
		{
			offset = leftPos + 1;
			int rightPos = str.indexOf( '>', leftPos );
			if( rightPos == -1 )
				continue;

			int key_len = rightPos - leftPos - 1;
			if( key_len < 1 )
				continue;

			String objectName = str.substring( leftPos + 1, leftPos + 1 + key_len );
			String referencedValue = throwIfAbsent ? jo.getString( objectName ) : jo.optString( objectName, "" );

			str = str.replace( str.substring( leftPos, leftPos + key_len + 2 ), referencedValue );
			--offset;
		}

		return str;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Заменить во всех строках объекта jo переменные на их значения:
	 *  вместо <<Some Name>>  - BER-TLV с соответствующим тегом;
	 *  вместо <Some Name>  - значение этого объекта (ищем в jo такое поле).
	 * @param throwIfAbsent - true - исключение, если поле "Some Name" не найдено в jo;
	 * false - если поле не найдено, будет использоваться пустая строка.
	 */
	public static void replaceVariables( JSONObject jo, ITagDictionary dict, boolean throwIfAbsent )
	{
		for( String key : jo.keySet() )
		{
			Object obj = jo.get( key );
			if( obj instanceof String )
				jo.put( key, replaceVariables( (String)obj, jo, dict, throwIfAbsent ) );
		}
	}

}
