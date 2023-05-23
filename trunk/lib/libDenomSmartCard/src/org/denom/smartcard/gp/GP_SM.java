// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.gp;

import org.denom.*;
import org.denom.crypt.*;
import org.denom.smartcard.*;

import static org.denom.Binary.*;
import static org.denom.Ex.*;

/**
 * Secure Messaging по GP, Secure Channel Protocol '02'.
 */
public class GP_SM implements ISM
{
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вывести производные ключи карты для SM с доменом GP, согласно одной из поддерживаемых схем.
	 * @param skdMethod - метод деривации ключей: "VISA2 или "EMV CPS 1.1", иначе - ошибка.
	 * @param baseKey - Базовый ключ.
	 * @param keyDiversData - Данные карты для диверсификации ключей [10 байт].
	 *   Первые 10 байт ответа карты на GP INITIALIZE UPDATE.
	 * @param encKey - [out] ключ шифрования [16 байт].
	 * @param macKey - [out] ключ MAC [16 байт].
	 * @param dekKey - [out] ключ для шифрования передаваемых ключей (DEK) [16 байт].
	 */
	public static void DeriveSMKeys( String skdMethod, final Binary baseKey, final Binary keyDiversData,
			Binary encKey, Binary macKey, Binary dekKey )
	{
		MUST( keyDiversData.size() == 10, "Key Diversification Data size must be 10 bytes" );
		Binary data = null;
		if( skdMethod.equalsIgnoreCase( "VISA2" ) )
		{
			data = keyDiversData.slice( 0, 2 ).add( keyDiversData.slice( 4, 4 ) );
		}
		else if( skdMethod.equalsIgnoreCase( "EMV CPS 1.1" ) )
		{
			data = keyDiversData.slice( 4, 6 );
		}
		else
		{
			THROW( "Wrong Key Derivation Method" );
		}

		DES2_EDE cipher = new DES2_EDE( baseKey );
		encKey.assign( cipher.encrypt( Bin( data, Bin("F001"), data, Bin("0F01") ), CryptoMode.ECB, AlignMode.NONE ) );
		macKey.assign( cipher.encrypt( Bin( data, Bin("F002"), data, Bin("0F02") ), CryptoMode.ECB, AlignMode.NONE ) );
		dekKey.assign( cipher.encrypt( Bin( data, Bin("F003"), data, Bin("0F03") ), CryptoMode.ECB, AlignMode.NONE ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вывести производные ключи карты для SM с доменом GP по схеме VISA2, см. метод DeriveSMKeys.
	 */
	public static void DeriveSMKeys_VISA2( final Binary baseKey, final Binary keyDiversData,
			Binary encKey, Binary macKey, Binary dekKey )
	{
		DeriveSMKeys( "VISA2", baseKey, keyDiversData, encKey, macKey, dekKey );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вывести производные ключи карты для SM с доменом GP по схеме EMV CPS 1.1, см. метод DeriveSMKeys.
	 */
	public static void DeriveSMKeys_EMVCPS11( final Binary baseKey, final Binary keyDiversData,
			Binary encKey, Binary macKey, Binary dekKey )
	{
		DeriveSMKeys( "EMV CPS 1.1", baseKey, keyDiversData, encKey, macKey, dekKey );
	}


	// =================================================================================================================
	// Сессионные ключи для проведения SM по GP.
	public static class SessionKeys
	{
		public Binary enc  = Bin();   // Ключ для шифрования командного APDU.
		public Binary cmac = Bin();   // Ключ для MAC командного APDU.
		public Binary rmac = Bin();   // Ключ для MAC ответного APDU.
		public Binary dek  = Bin();   // Ключ для шифрования ключей, передаваемых в карту при смене ключей домена.
		public String skdMethod = ""; // Схема деривации ключей.

		public SessionKeys() {}

		// -------------------------------------------------------------------------------------------------------------
		public SessionKeys clone()
		{
			SessionKeys copy = new SessionKeys();
			copy.enc  = enc.clone();
			copy.cmac = cmac.clone();
			copy.rmac = rmac.clone();
			copy.dek  = dek.clone();
			copy.skdMethod = skdMethod;
			return copy;
		}

		// -------------------------------------------------------------------------------------------------------------
		/**
		 * Сгенерировать сессионные ключи из ключей домена.
		 * @param encKey - ключ домена для шифрования данных команды
		 * @param macKey - ключ домена для вычисления MAC команды
		 * @param dekKey - ключ для шифрования секретов (ключей).
		 * @param ssc - счётчик сессий, полученный от карты в GP INITIALIZE UPDATE.
		 */
		public SessionKeys( final Binary encKey, final Binary macKey, final Binary dekKey, final Binary ssc )
		{
			MUST( ssc.size() == 2, "Счётчик сессий должен быть размером 2 байта" );
			int sz = DES2_EDE.KEY_SIZE;
			MUST( (encKey.size() == sz) && (macKey.size() == sz) && (dekKey.size() == sz), "Некорректный размер ключа" );

			Binary data = Bin( "0101" ).add( ssc ).add( Bin(12) );
			
			cmac = new DES2_EDE( macKey ).encrypt( data, CryptoMode.CBC, AlignMode.NONE );
			
			data.set( 1, 0x02 );
			rmac = new DES2_EDE( macKey ).encrypt( data, CryptoMode.CBC, AlignMode.NONE );

			data.set( 1, 0x82 );
			enc  = new DES2_EDE( encKey ).encrypt( data, CryptoMode.CBC, AlignMode.NONE );

			data.set( 1, 0x81 );
			dek  = new DES2_EDE( dekKey ).encrypt( data, CryptoMode.CBC, AlignMode.NONE );
			
			skdMethod = "GP";
		}

		// -------------------------------------------------------------------------------------------------------------
		/**
		 * Вычислить сессионные ключи, сгенерировав ключи карты по одной из схем.
		 * @param skdMethod - метод деривации ключей: "VISA2 или "EMV CPS 1.1", иначе - ошибка.
		 * @param baseKey - ключ домена.
		 * @param keyDiversData - данные от карты для генерации производных ключей.
		 *   (первые 10 байт ответа на GP INITIALIZE UPDATE).
		 * @param ssc - счётчик сессий, полученный от карты в GP INITIALIZE UPDATE.
		 * @return сессионные ключи.
		 */
		public static SessionKeys Derive( String skdMethod, final Binary baseKey,
				final Binary keyDiversData, final Binary ssc )
		{
			Binary cardEncKey = Bin();
			Binary cardMacKey = Bin();
			Binary cardDekKey = Bin();
			DeriveSMKeys( skdMethod, baseKey, keyDiversData, cardEncKey, cardMacKey, cardDekKey );

			SessionKeys sk = new SessionKeys( cardEncKey, cardMacKey, cardDekKey, ssc );
			sk.skdMethod = skdMethod;
			return sk;
		}

	} // class SessionKeys

	// =================================================================================================================

	public int keysVersion = 0; // Версия ключей (байт, идентифицирующий KeySet, возвращается в ответе карты на GP INITIALIZE UPDATE).

	public DES2_EDE dekCipher = new DES2_EDE( Bin( 16 ) );

	// Шифр для шифрования сообщения
	private DES2_EDE encCipher = new DES2_EDE( Bin( 16 ) );
	// Шифр для вычисления C-MAC сообщения
	private DES2_EDE cmacCipher = new DES2_EDE( Bin( 16 ) );
	// Шифр для вычисления R-MAC сообщения
	private DES2_EDE rmacCipher = new DES2_EDE( Bin( 16 ) );

	private int securityLevel;

	// ICV (Initial Chaining Value)
	private Binary icv = Bin( 8 );
	private Binary rmac = Bin( 8 );

	private Binary rmacBuf;

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Пустой конструктор для последующей инициализации.
	 */
	public GP_SM()
	{
		rmacBuf = Bin();
		rmacBuf.reserve( 255 + 258 + 6 ); // Оптимизация - однократное выделение памяти
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Инициализация SM.
	 * @param keys - выработанные ранее сессионные ключи для проведения SM.
	 * @param icv - инициализирующий вектор.
	 * @param secLevel - режим, см. константы в GP.SecLevel
	 */
	public void init( final SessionKeys keys, int secLevel, final Binary icv, int keysVersion )
	{
		MUST( Int.isU8( secLevel ), "Must be U8" );

		encCipher.setKey( keys.enc );
		cmacCipher.setKey( keys.cmac );
		rmacCipher.setKey( keys.rmac );
		dekCipher.setKey( keys.dek );
		this.icv.assign( icv );
		this.rmac.assign( icv );
		this.securityLevel = secLevel;
		this.keysVersion = keysVersion;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public CApdu encryptCommand( CApdu noSM )
	{
		int Ne;
		Binary mac = Bin();

		// буфер для R-MAC
		if( (securityLevel & GP.SecLevel.RMAC ) != 0x00 )
		{
			rmacBuf.resize( 0 );
			rmacBuf.add( noSM.cla );
			rmacBuf.add( noSM.ins );
			rmacBuf.add( noSM.p1 );
			rmacBuf.add( noSM.p2 );
			rmacBuf.add( Num_Bin( noSM.Nc(), 0 ) );
			rmacBuf.add( noSM.data );
		}

		if( (securityLevel & GP.SecLevel.CMAC) != 0x00 )
		{
			Binary cmacBuf = Bin();
			cmacBuf.reserve( 5 + noSM.data.size() );
			cmacBuf.add( noSM.cla | 0x04 );
			cmacBuf.add( noSM.ins );
			cmacBuf.add( noSM.p1 );
			cmacBuf.add( noSM.p2 );

			cmacBuf.add( Num_Bin( noSM.Nc() + 8, 0 ) );
			cmacBuf.add( noSM.data );

			DES icv_cipher = new DES( cmacCipher.getKey().slice( 0, 8 ) );
			Binary icv_encrypted = icv_cipher.encrypt( icv, CryptoMode.ECB, AlignMode.NONE );

			mac = cmacCipher.calcCCS( cmacBuf, AlignMode.BLOCK, CCSMode.FAST, icv_encrypted );
			icv = mac;
		}

		Binary data_field;
		if( (securityLevel & 0x02) != 0x00 ) // Decryption
		{
			data_field = noSM.data.empty() ? Bin() : encCipher.encrypt( noSM.data, CryptoMode.CBC, AlignMode.BLOCK );
		}
		else
		{
			data_field = noSM.data.clone();
		}

		if( (securityLevel & GP.SecLevel.CMAC) != 0x00 )
		{
			data_field.add( mac );
		}

		Ne = noSM.getNe();
		if( (securityLevel & GP.SecLevel.RMAC) != 0x00 )
		{
			Ne += 8;
		}

		CApdu withSM = new CApdu( (securityLevel != 0x00) ? (noSM.cla | 0x04) : noSM.cla,
			noSM.ins, noSM.p1, noSM.p2, data_field, Ne );

		return withSM;
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public RApdu decryptResponse( final RApdu withSM )
	{
		RApdu noSM = withSM.clone();

		if( (securityLevel & GP.SecLevel.RMAC) != 0x00 )
		{
			MUST( noSM.response.size() >= 8, "Некорректная длина ответа карты" );

			int respDataSize = noSM.response.size() - 8;
			rmacBuf.add( respDataSize );

			if( respDataSize != 0 )
			{
				rmacBuf.add( noSM.response.slice( 0, respDataSize ) );
			}

			rmacBuf.addU16( noSM.status );

			if( (rmac.size() % DES2_EDE.BLOCK_SIZE) != 0 )
			{
				rmac.add( Bin( DES2_EDE.BLOCK_SIZE - rmac.size(), 0 ) );
			}

			Binary rmacCCS = rmacCipher.calcCCS( rmacBuf, AlignMode.BLOCK, CCSMode.FAST, rmac );
			MUST( rmacCCS.equals( noSM.response.slice( respDataSize, 8 ) ), "Не сошелся R-MAC" );
			rmac = rmacCCS;

			noSM.response = noSM.response.slice( 0, respDataSize );
		}

		return noSM;
	}

	// ---------------------------------------------------------------------------------------------------------------------
	public static Binary CalcGP_Cryptogram( final Binary encSessionKey, final Binary divData )
	{
		return new DES2_EDE( encSessionKey ).calcCCS( divData, AlignMode.BLOCK, CCSMode.CLASSIC );
	}

	// ---------------------------------------------------------------------------------------------------------------------
	/**
	 * Сгенерировать сессионные ключи для SM на основе ключей терминала и ответа карты.
	 * @param encKey - ключ шифрования данных команды.
	 * @param macKey - ключ подписывания данных команды.
	 * @param dekKey - ключ шифрования ключей.
	 * @param hostChallenge - случайное число терминала.
	 * @param gpInitUpdateResponse - ответ карты на команду GP INITIALIZE UPDATE.
	 * @return сессионные ключи, если криптограмма карты сформирована на тех же ключах,
	 * что имеются у терминала; null - если ключи не соответствуют криптограмме карты.
	 */
	public static SessionKeys genSessionKeys( final Binary encKey, final Binary macKey, final Binary dekKey,
		final Binary hostChallenge, final Binary gpInitUpdateResponse )
	{
		Binary keyDiversData   = gpInitUpdateResponse.slice( 0, 10 );
		//Binary keyInfo         = gpInitUpdateResponse.slice( 10, 2 );
		Binary ssc             = gpInitUpdateResponse.slice( 12, 2 );
		Binary cardChallenge   = gpInitUpdateResponse.slice( 14, 6 );
		Binary cardCryptogram  = gpInitUpdateResponse.slice( 20, 8 );

		// Пробуем использовать 3 схемы генерации производных ключей, какая подойдёт.

		SessionKeys sessionKeys = new SessionKeys( encKey, macKey, dekKey, ssc );

		Binary divData = Bin().add( hostChallenge ).add( ssc ).add( cardChallenge );
		Binary cryptogram = CalcGP_Cryptogram( sessionKeys.enc, divData );

		if( !cardCryptogram.equals( cryptogram ) )
		{	// Пробуем использовать схему генерации производных ключей EMV CPS 1.1.
			// В качестве базового берём первый ключ - encKey.
			sessionKeys = SessionKeys.Derive( "EMV CPS 1.1", encKey, keyDiversData, ssc );
			cryptogram = CalcGP_Cryptogram( sessionKeys.enc, divData );
		}

		if( !cardCryptogram.equals( cryptogram ) )
		{ // Пробуем VISA2
			sessionKeys = SessionKeys.Derive( "VISA2", encKey, keyDiversData, ssc );
			cryptogram = CalcGP_Cryptogram( sessionKeys.enc, divData );
		}

		return cardCryptogram.equals( cryptogram ) ? sessionKeys : null;
	}

	// ---------------------------------------------------------------------------------------------------------------------
	/**
	 * Формирует CApdu для завершения инициализации SM, инициализирует объект GP_SM
	 */
	public static CApdu formExtAuth( final Binary cardResponse, int secLevel, final Binary hostChallenge,
		SessionKeys sessionKeys, GP_SM sm )
	{
		Binary ssc = cardResponse.slice( 12, 2 );
		Binary cardChallenge = cardResponse.slice( 14, 6 );
		Binary hostCryptogram = CalcGP_Cryptogram( sessionKeys.enc, Bin().add( ssc ).add( cardChallenge ).add( hostChallenge ) );

		CApdu capdu = ApduGP.ExternalAuthenticate( secLevel, hostCryptogram );

		Binary header = Bin();
		header.reserve( 5 );
		header.add( capdu.cla );
		header.add( capdu.ins );
		header.add( capdu.p1 );
		header.add( capdu.p2 );
		header.add( capdu.Nc() + 8 );

		Binary mac = new DES2_EDE( sessionKeys.cmac ).calcCCS( Bin( header, hostCryptogram ), AlignMode.BLOCK, CCSMode.FAST );
		capdu.data = Bin( hostCryptogram, mac );
		
		sm.init( sessionKeys, secLevel, mac, cardResponse.get( 10 ) );
		return capdu;
	}

	// ---------------------------------------------------------------------------------------------------------------------
	/**
	 * Открыть сессию SM, Провести взаимную аутентификацию по GP SCP02 и выработать сессионные ключи.
	 * Приложение должно быть предварительно выбрано.
	 * @param keyVersion - Версия ключа.
	 * @param encKey - Secure Channel Encryption Key.
	 * @param macKey - Secure Channel MAC Key.
	 * @param dekKey - Secure Channel Data Encryption Key
	 * @param secLevel - Уровень безопасности, см. константы - {@link GP.SecLevel}
	 * @return Инициализированный объект GP_SM.
	 */
	public static GP_SM open( int keyVersion, final Binary encKey, final Binary macKey, final Binary dekKey,
		int secLevel, CardReader cr )
	{
		MUST( Int.isU8( secLevel ), "Must be U8" );

		Binary hostChallenge = Bin().random( 8 );
		cr.Cmd( ApduGP.InitializeUpdate( hostChallenge, keyVersion ) );

		SessionKeys sessionKeys = genSessionKeys( encKey, macKey, dekKey, hostChallenge, cr.resp );
		MUST( sessionKeys != null, "Ключи терминала не соответствуют криптограмме карты" );

		GP_SM sm = new GP_SM();
		cr.Cmd( formExtAuth( cr.resp, secLevel, hostChallenge, sessionKeys, sm ) );
		return sm;
	}

	// ---------------------------------------------------------------------------------------------------------------------
	/**
	 * Открыть сессию SM, Провести взаимную аутентификацию по GP SCP02 и выработать сессионные ключи.
	 * Одинаковое значение трёх ключей домена. Домен должен быть предварительно выбран.
	 */
	public static GP_SM open( int keyVersion, final Binary baseKey, int secLevel, CardReader cr )
	{
		return open( keyVersion, baseKey, baseKey, baseKey, secLevel, cr );
	}

	// ---------------------------------------------------------------------------------------------------------------------
	/**
	 * Открыть сессию SM по GP SCP02 для карты в ридере cr.
	 * Домен в карте должен быть предварительно выбран.
	 * Ключи берём из SecurityModule.
	 */
	public static GP_SM open( CardReader cr, int keyVersion, int smSecurityLevel, ISecurityModuleGP securityModule )
	{
		MUST( Int.isU8( smSecurityLevel ), "Must be U8" );

		Binary hostChallenge = Bin().random( 8 );
		cr.Cmd( ApduGP.InitializeUpdate( hostChallenge, keyVersion ) );
		int keysVersion = cr.resp.get( 10 );

		Binary b = securityModule.gpGenSmSessionKeys( smSecurityLevel, hostChallenge, cr.resp );
		MUST( !b.empty(), "Wrong card cryptogram or incorrect domain keys" );
		SessionKeys keys = new SessionKeys();
		keys.enc  = b.slice( 0,  16 );
		keys.cmac = b.slice( 16, 16 );
		keys.rmac = b.slice( 32, 16 );
		keys.dek  = b.slice( 48, 16 );
		Binary icv = b.slice( 64, 8 );

		CApdu capdu = new CApdu( b.slice( 72, 21 ) );
		capdu.description = "{GP} EXTERNAL AUTHENTICATE";
		cr.Cmd( capdu );

		GP_SM sm = new GP_SM();
		sm.init( keys, smSecurityLevel, icv, keysVersion );
		return sm;
	}
}
