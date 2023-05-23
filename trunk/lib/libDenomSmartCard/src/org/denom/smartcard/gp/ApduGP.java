// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.gp;

import org.denom.*;
import org.denom.format.BerTLV;
import org.denom.crypt.*;
import org.denom.smartcard.*;

import static org.denom.Binary.*;
import static org.denom.Ex.*;
import static org.denom.format.BerTLV.Tlv;
import static org.denom.format.LV.*;

/**
 * Формирование CApdu работы с доменом по стандарту Global Platform.
 */
public class ApduGP
{
	/**
	 * Команда GET DATA с чётным INS (0xCA).<br>
	 * Считать объект данных с указанным тегом.
	 * @param tag - 1- или 2-х-байтовый тег.
	 * @param len - Размер ожидаемого ответа.
	 */
	public static CApdu GetData( int tag )
	{
		MUST( Int.isU16( tag ), "Wrong Tag" );
		CApdu ap = new CApdu( 0x80, 0xCA, tag >>> 8, (tag & 0xFF), Bin(), CApdu.MAX_NE, "{GP} GET DATA" );
		ap.isTlvData = true;
		return ap;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * INSTALL (for load) [1] 11.5.2.3.1. Инициировать загрузку пакета.
	 * @param pkgAID - AID пакета.
	 * @param sdAID - AID домена.
	 * @param capHash - Хеш CAP-файла.
	 */
	public static CApdu InstallForLoad( final Binary pkgAID, final Binary sdAID, final Binary capHash )
	{
		Binary data = LV1( pkgAID, sdAID, capHash, Bin(), Bin() );
		return new CApdu( 0x80, 0xE6, 0x02, 0x00, data, CApdu.MAX_NE, "{GP} INSTALL (for load)" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * INSTALL (for install) [1] 11.5.2.3.2. Создать инстанс приложения. 
	 * @param pkgAID - AID пакета.
	 * @param classAID - AID класса апплета.
	 * @param instanceAID - AID инстанса.
	 * @param appParameters - Параметры инсталляции.
	 * @param privileges - Привилегии создаваемого приложения.
	 * @param systemParameters - Системные параметры.
	 */
	public static CApdu InstallForInstall( final Binary pkgAID, final Binary classAID, final Binary instanceAID, 
		final Binary appParameters, int privileges, final Binary systemParameters )
	{
		// Привилегии
		Binary priv = Num_Bin( privileges, 3 );
		if( (priv.get( 1 ) == 0x00) && (priv.get( 2 ) == 0x00) )
		{
			priv = priv.slice( 0, 1 );
		}

		// Параметры установки 
		Binary paramsTagged = Tlv( 0xC9, appParameters ); // tag C9 -> Application Specific Parameters
		if( !systemParameters.empty() )
		{
			paramsTagged.add( Tlv( 0xEF, systemParameters ) ); // tag EF -> System Specific Parameters
		}

		Binary data = LV1( pkgAID, classAID, instanceAID, priv, paramsTagged, Bin() );

		return new CApdu( 0x80, 0xE6, 0x0C, 0x00, data, CApdu.MAX_NE, "{GP} INSTALL (for install)" );
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * INSTALL (for install) [1] 11.5.2.3.2. Создать инстанс приложения. 
	 * @param pkgAID - AID пакета.
	 * @param classAID - AID класса апплета.
	 * @param instanceAID - AID инстанса.
	 * @param params - Параметры инсталляции.
	 * @param privileges - Привилегии создаваемого приложения.
	 */
	public static CApdu InstallForInstall( final Binary pkgAID, final Binary classAID, final Binary instanceAID,
		final Binary params, int privileges )
	{
		return InstallForInstall( pkgAID, classAID, instanceAID, params, privileges, Bin() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static CApdu InstallForInstall( String pkgAID, String  classAID, String instanceAID, 
			String params, int privileges )
	{
		return InstallForInstall( Bin(pkgAID), Bin(classAID), Bin(instanceAID), Bin(params), privileges );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * LOAD. Загрузить первую часть CAP-файла.
	 * @param capSize - Полный размер CAP-файла.
	 * @param capPart - Первая часть CAP-файла.
	 * @param dapVal - CCS хеша CAP-файла (опционально).
	 */
	public static CApdu LoadFirstBlock( int capSize, final Binary capPart, final Binary dapVal )
	{
		Binary data = Bin();
		if( !dapVal.empty() )
		{
			// пока AID SD игнорируется картой, поэтому посылаем пустышку
			// subtag 4F -> SD AID
			// subtag C3 -> Load File Data Block Signature
			Binary tlv1 = Tlv( 0x4F, Bin() );
			Binary tlv2 = Tlv( 0xC3, dapVal );

			// tag E2 -> DAP BLOCK
			data.add( Tlv( 0xE2, Bin( tlv1, tlv2 ) ) );
		}

		BerTLV.appendTlvTag( data, 0xC4 );
		BerTLV.appendTlvLen( data, capSize );
		data.add( capPart );

		boolean isLastBlock = (capSize == capPart.size());

		return new CApdu( 0x80,  0xE8, isLastBlock ? 0x80 : 0x00,  0x00,  data, CApdu.MAX_NE, "{GP} LOAD (block 0)" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * LOAD. Загрузить очередную часть CAP-файла.
	 * @param blockNumber - Порядковый номер части.
	 * @param capPart - Очередная часть CAP-файла.
	 * @param isLastBlock - Признак последнего пакета.
	 */
	public static CApdu LoadNextBlock( int blockNumber, final Binary capPart, boolean isLastBlock )
	{
		//MUST( Int.isU8( blockNumber ), "Block number must be <= 255" );

		int p1 = isLastBlock ? 0x80 : 0x00;

		// Отбрасываем старшую часть номера блока.
		// Несоответствие стандарту, но для загрузки больших CAP-файлов через эту команду, можно сделать так,
		// чтобы процесс загрузки не останавливался на терминале.
		return new CApdu( 0x80, 0xE8, p1, (blockNumber & 0xFF), capPart, CApdu.MAX_NE, "{GP} LOAD (block "+ blockNumber + ")" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * DELETE. 11.2. Удалить приложение или пакет.
	 * @param aid AID удаляемого приложения или пакета.
	 * @param deleteMode - Режим удаления - {@link GP.DelMode}
	 */
	public static CApdu Delete( final Binary aid, int deleteMode )
	{
		MUST( Int.isU8( deleteMode ), "delete mode must be U8" );

		// tag 4F -> Executable Load File or Application AID
		Binary data = Tlv( 0x4F, aid );
		CApdu ap = new CApdu( 0x80, 0xE4, 0x00, deleteMode, data, CApdu.MAX_NE, "{GP} DELETE" );
		ap.isTlvData = true;
		return ap;
	}

	public static CApdu Delete( String aid, int deleteMode )
	{
		return Delete( Bin(aid), deleteMode );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * GET STATUS. Получить информацию о приложении. 
	 * @param target - Тип приложения - {@link GP.GetStatusTarget}.
	 * @param aid - AID приложения.
	 */
	public static CApdu GetStatus( int target, final Binary aid )
	{
		MUST( Int.isU8( target ), "status target must be U8" );

		CApdu ap = new CApdu( 0x80, 0xF2, target, 0x00, Tlv( 0x4F, aid ), CApdu.MAX_NE, "{GP} GET STATUS" );
		ap.isTlvData = true;
		return ap;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * SET STATUS. 11.10. Изменить текущее состояние жизненного цикла приложения.
	 * @param setStatusTarget - Тип приложения - {@link GP.SetStatusTarget}.
	 *   При GP_STATUS_ISD параметр aid игнорируется/
	 * @param appState - состояние приложения - {@link GP.AppState} (подробнее - 11.1.1)
	 * @param aid- AID приложения, параметры которого хотим изменить
	 */
	public static CApdu SetStatus( int setStatusTarget, int appState, final Binary aid )
	{
		MUST( Int.isU8( setStatusTarget ), "status target must be U8" );
		MUST( Int.isU8( appState ), "status must be U8" );

		return new CApdu( 0x80, 0xF0, setStatusTarget, appState, aid, 0, "{GP} SET STATUS" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * PUT KEY. 11.8. Командное APDU: Добавить/заменить существующий ключ.
	 * @param keyId - Идентификатор ключа.
	 * @param keyType - Тип ключа (см. 11.1.8).
	 * @param keyVerCurrent - Текущий номер версии ключа (0x00 - для создания нового ключа/группы).
	 * @param keyVerNew - Новый номер версии ключа.
	 * @param keyVal - Значение ключа.
	 */
	public static CApdu PutKey( int keyId, int keyType, int keyVersionCurrent, int keyVersionNew,
			final Binary keyVal, final Binary dekSessionKey )
	{
		MUST( (keyId >= 0) && (keyId <= 127), "Wrong KeyId" );
		MUST( (keyVersionCurrent >= 0) && (keyVersionCurrent <= 127), "Wrong keyVersionCurrent" );
		MUST( (keyVersionNew >= 0) && (keyVersionNew <= 127), "Wrong keyVersionNew" );

		Binary data = Bin().reserve( 30 );
		data.add( keyVersionNew );
		data.add( Build3DesKeyData( keyType, keyVal, dekSessionKey ) );

		return new CApdu( 0x80, 0xD8, keyVersionCurrent, keyId, data, CApdu.MAX_NE, "{GP} PUT KEY" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static Binary Build3DesKeyData( int keyType, final Binary key, final Binary dekSessionKey )
	{
		Binary encryptedKey = dekSessionKey.empty()? key :
			new DES2_EDE( dekSessionKey ).encrypt( key, CryptoMode.ECB, AlignMode.NONE );

		Binary data = Bin().reserve( 30 );
		data.add( keyType );
		data.add( LV1( encryptedKey ) );
		data.add( LV1( DES2_EDE.calcKCV( key ) ) );

		return data;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать 3 DES3-ключа (KeySet).
	 * @param keyId - Идентификатор ключа, например, 1 (SM ENC), другие варианты - см. спецификации GP.
	 * @param keyType - тип ключа. 0x80 - для ключей DES3.
	 * @param keyVersionCurrent - текущая версия ключей, идентифицирует KeySet в карте, в котором меняем ключи.
	 *   0 - создать новый KeySet.
	 * @param keyVersionNew - версия загружаемого KeySet-а.
	 * @param dekSessionKey - сессионный ключ для шифрования передаваемых ключей.
	 */
	public static CApdu PutKey_KeySet( int keyId, int keyType, int keyVersionCurrent, int keyVersionNew,
		final Binary key1, final Binary key2, final Binary key3, final Binary dekSessionKey )
	{
		MUST( (keyId >= 0) && (keyId <= 127), "Wrong KeyId" );
		MUST( (keyVersionCurrent >= 0) && (keyVersionCurrent <= 127), "Wrong keyVersionCurrent" );
		MUST( (keyVersionNew >= 0) && (keyVersionNew <= 127), "Wrong keyVersionNew" );

		// ключей несколько
		int p2 = 0x80 | keyId;

		Binary data = Bin().reserve( 100 );
		data.add( keyVersionNew );
		data.add( Build3DesKeyData( keyType, key1, dekSessionKey ) );
		data.add( Build3DesKeyData( keyType, key2, dekSessionKey ) );
		data.add( Build3DesKeyData( keyType, key3, dekSessionKey ) );

		return new CApdu( 0x80, 0xD8, keyVersionCurrent, p2, data, CApdu.MAX_NE, "{GP} PUT KEY DES3 KeySet" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * INITIALIZE UPDATE. Начало взаимной аутентификации по SCP02.
	 * @param challenge - Случайное число терминала (8 байт).
	 * @param keyVer - Версия ключа/ключей.
	 */
	public static CApdu InitializeUpdate( final Binary challenge, int keyVer )
	{
		MUST( Int.isU8( keyVer ), "Wrong Key Version" );
		return new CApdu( 0x80, 0x50, keyVer, 0x00, challenge, CApdu.MAX_NE, "{GP} INITIALIZE UPDATE" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * EXTERNAL AUTHENTICATE.
	 * @param GP_SecurityLevel - {@link GP.SecLevel}.
	 * @param hostCryptogram - Криптограмма терминала.
	 */
	public static CApdu ExternalAuthenticate( int GP_SecurityLevel, final Binary hostCryptogram )
	{
		MUST( Int.isU8( GP_SecurityLevel ), "security level must be U8" );
		return new CApdu( 0x84, 0x82, GP_SecurityLevel, 0x00, hostCryptogram, 0, "{GP} EXTERNAL AUTHENTICATE" );
	}
}
