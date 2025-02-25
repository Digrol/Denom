// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv;

import java.math.BigInteger;

import org.denom.Binary;
import org.denom.Int;
import org.denom.crypt.*;
import org.denom.crypt.ec.ECAlg;
import org.denom.crypt.ec.Fp.FpCurveAbstract;
import org.denom.crypt.hash.IHash;

import static org.denom.Binary.Bin;
import static org.denom.Ex.MUST;

/**
 * Криптографические примитивы для EMV-систем - эмуляторов карт, терминалов и тестов.
 * EMV Contactless Specifications for Payment Systems, Book E, Security and Key Management.
 */
public class EmvCrypt
{
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Генерация DES3 ключа карты (MK) из мастер-ключа эмитента (IMK).
	 * @param issuerKey - IMK - 3DES-ключ эмитента.
	 * @param Y - [8 байт], данные для получения производного ключа: 7 последних байт PAN + PAN SN.
	 * @return Производный ключ.
	 */
	public static Binary generateIcc3DesMK( final Binary issuerKey, final Binary Y )
	{
		MUST( issuerKey.size() == DES2_EDE.KEY_SIZE, "Некорректный размер ключа" );
		MUST( Y.size() == 8, "Некорректный размер derivation data" );

		Binary Y2 = Binary.xor( Y, Bin( 8, 0xFF ) );
		Binary Z = Bin( Y, Y2 );
		DES2_EDE alg = new DES2_EDE( issuerKey );
		Z = alg.encrypt( Z, CryptoMode.ECB, AlignMode.NONE );
		DES.setOddParityBits( Z );
		return Z;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Генерация DES3 ключа карты (MK) из мастер-ключа эмитента (IMK).
	 * Book E, 4.1.A
	 */
	public static Binary generateIcc3DesMK( final Binary issuerKey, final Binary PAN, final Binary PAN_SN )
	{
		// PAN || PSN
		Binary X = Bin( PAN, PAN_SN );
		// Rightmost 16 digits of X
		Binary Y = X.last( 8 );
		return generateIcc3DesMK( issuerKey, Y );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Генерация AES ключа карты (MK) из мастер-ключа эмитента (IMK).
	 * Book E, 4.1.C
	 */
	public static Binary generateIccAesMK( final Binary IMK, final Binary PAN, final Binary PAN_SN )
	{
		// X = PAN || PSN
		// Pad X to the left with zero-digits to form a 16-byte number Y
		Binary Y = Bin( Bin( 16 - PAN.size() - PAN_SN.size() ), PAN, PAN_SN );
		new AES( IMK ).encryptBlock( Y );
		return Y;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сгенерировать EC ключ для карты или эмитента.
	 * Book E, 8.8.5
	 * @param ecAlg с кривой FP
	 * @return Только X-координата публичного ключа.
	 */
	public static Binary generateEccKey( ECAlg ecAlg )
	{
		FpCurveAbstract curve = (FpCurveAbstract)ecAlg.getCurve();
		int nSize = curve.getNField();

		BigInteger p = curve.getP();
		BigInteger p2 = p.add( BigInteger.ONE ).divide( BigInteger.valueOf( 2 ) );

		// Repeatedly generate until the y-coordinate of d*G is less than (p+1)/2
		BigInteger y = null;
		Binary pub;
		do
		{
			ecAlg.generateKeyPair();
			pub = ecAlg.getPublic( false );
			y = new BigInteger( Bin( Bin( 1 ), pub.last( nSize ) ).getBytes() );
		}
		while( y.compareTo( p2 ) != -1 );

		return pub.slice( 1, nSize );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Book E, 8.8.4 Point Finding.
	 * @param publicKeyX - Координата X.
	 */
	public static void restorePublicKey( ECAlg ecAlg, final Binary publicKeyX )
	{
		int NField = ((FpCurveAbstract)ecAlg.getCurve()).getNField();

		ecAlg.setPublic( Bin(1, 0x02).add( publicKeyX ) );
		Binary key02 = ecAlg.getPublic( false );
		key02 = key02.last( NField );

		ecAlg.setPublic( Bin(1, 0x03).add( publicKeyX ) );
		Binary key03 = ecAlg.getPublic( false );
		key03 = key03.last( NField );

		// из двух точек берем ту, у которой Y меньше.
		if( key02.compareTo( key03 ) == -1 )
			ecAlg.setPublic( Bin(1, 0x02).add( publicKeyX ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вычислить Card blinded public key - Pc.
	 * Карта вычисляет Pc и передаёт терминалу в GPO Response.
	 * Book E, 7.1  BDH Initialisation.
	 * @param r - blinding factor, длина = размеру параметров кривой. 1 < r < n-1.
	 * @param Qc - публичный ключ карты.
	 * @return Pc = r * Qc.
	 */
	public static Binary BDHCalcPc( final ECAlg Qc, final Binary r )
	{
		ECAlg ecAlg = Qc.clone();
		ecAlg.setPrivate( r );
		Binary Pc = ecAlg.calcDH( Qc.getPublic( false ) );
		return Pc;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вычислить BDH shared secret (z) со стороны карты.
	 * Карта вычисляет его в GPO для генерации сессионных ключей.
	 * Book E, 7.2  BDH Key Derivation.
	 * @param Qk - Публичный ECC ключ терминала.
	 * @param Dc - секретный ключ карты.
	 * @param r - blinding factor, длина = размеру параметров кривой. 1 < r < n-1.
	 * @return z - shared secret = Dc * r * Qk.
	 */
	public static Binary BDHCalcZ( final ECAlg Qk, final Binary Dc, final Binary r )
	{
		ECAlg ecAlg = Qk.clone();
		ecAlg.setPrivate( Dc );
		Binary p = Bin(1, 0x02).add( ecAlg.calcDH( Qk.getPublic( false ) ) );
		ecAlg.setPrivate( r );
		Binary z = ecAlg.calcDH( p );
		return z;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вычислить BDH shared secret (z) со стороны терминала.
	 * Book E, 7.2  BDH Key Derivation.
	 * @param Dk - Секретный ключ терминала.
	 * @param Pc - Card blinded public key, длина = размеру параметров кривой. То, что карта возвращает в GPO.
	 * @return z - shared secret = Dk * Pc.
	 */
	public static Binary BDHCalcZ( final ECAlg Dk, final Binary Pc )
	{
		Binary PcPoint = Bin(1, 0x02).add( Pc );
		Binary z = Dk.calcDH( PcPoint );
		return z;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вычислить 16-байтный производный ключ - Kd.
	 * Book E, 7.2  BDH Key Derivation.
	 * @param z - shared secret, см. BDHCalcSecret.
	 * @return Kd - derivation key [16 байт].
	 */
	public static Binary BDHCalcKd( final Binary z )
	{
		// Let V be 16 zero bytes.
		// Kd = AES-CMAC (V) [Z]
		AES aes = new AES( Bin(16) );
		Binary Kd = aes.calcCMAC( z, null );
		return Kd;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param b1 первый байт в данных для вывода ключа - "номер ключа" - 01, 02, 03.
	 * SK = AES (Kd) [ b1  || '01' || '00' || '54334A325957773D' || 'A5A5A5'|| '0180']
	 * @return sessionKey [16 байт]
	 */
	public static Binary BDHCalcSessionKey( final Binary Kd, int b1 )
	{
		AES aes = new AES( Kd );
		Binary b = Bin( 1, b1 ).add( "01 00 54334A325957773D A5A5A5 0180" );
		aes.encryptBlock( b );
		return b;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Derive the session key for confidentiality SKc.
	 * Book E, 7.2  BDH Key Derivation.
	 * SKc = AES (Kd) ['01' || '01' || '00' || '54334A325957773D' || 'A5A5A5'|| '0180']
	 * @return SKc [16 байт]
	 */
	public static Binary BDHCalcSKc( final Binary Kd )
	{
		return BDHCalcSessionKey( Kd, 0x01 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Derive the session key for integrity SKi.
	 * Book E, 7.2  BDH Key Derivation.
	 * SKi = AES (Kd) ['02' || '01' || '00' || '54334A325957773D' || 'A5A5A5'|| '0180']
	 * @return SKi [16 байт]
	 */
	public static Binary BDHCalcSKi( final Binary Kd )
	{
		return BDHCalcSessionKey( Kd, 0x02 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вычислить сессионные ключи BDH.
	 * @param Dk - Секретный ключ терминала.
	 * @param Pc - Card blinded public key, длина = размеру параметров кривой. То, что карта возвращает в GPO.
	 * @return Конкатенация SKc || SKi
	 */
	public static Binary BDHCalcSessionKeys( final ECAlg Dk, final Binary Pc )
	{
		Binary z = BDHCalcZ( Dk, Pc );
		Binary Kd = BDHCalcKd( z );
		Binary SKc = BDHCalcSessionKey( Kd, 0x01 );
		Binary SKi = BDHCalcSessionKey( Kd, 0x02 );
		return Bin( SKc, SKi );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Book E,  8.6.2  AES-CTR.
	 * @param messageCounter (U16). Incremented after operation.
	 * @param data input message (plain or crypt).
	 * @return output message C (crypt or plain).
	 */
	public static Binary cryptAesCTR( AES aes, Int messageCounter, final Binary data )
	{
		MUST( Int.isU16( messageCounter.val ), "Wrong messageCounter for AES-CTR" );
		Binary SV = Bin( aes.getBlockSize() );
		SV.setU16( 0, messageCounter.val );
		Binary C = aes.cryptCTR( data, SV );
		messageCounter.val++;
		return C;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static Binary calcAesMac( AES aes, Int messageCounter, final Binary data )
	{
		Binary b = Bin().addU16( messageCounter.val ).add( data );
		Binary mac = aes.calcCMAC( b, null ).first( 8 );
		messageCounter.val++;
		return mac;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param Er - encrypted blinding factor.
	 * @param CMC - Card Message Counter, incremented after operation.
	 * Recover 'r' from 'Encrypted r'
	 */
	public static Binary BDHRecoverR( AES SKc, final Binary Er, Int CMC )
	{
		return cryptAesCTR( SKc, CMC, Er );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * 7.3  BDH Blinding Factor Validation.
	 * @param Pc - blinded card public key.
	 */
	public static boolean BDHValidate( ECAlg Qc, final Binary r, final Binary Pc )
	{
		ECAlg ec = Qc.clone();
		ec.setPrivate( r );
		Binary QcPoint = Qc.getPublic( false );
		Binary myPc = ec.calcDH( QcPoint );
		return Pc.equals( myPc );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * 8.6.5  AES-CMAC+
	 */
	public static Binary calcAesCmacPlus( AES aes, Binary message )
	{
		Binary cmac = aes.calcCMAC( message, null );
		cmac = aes.decrypt( cmac, CryptoMode.CBC, AlignMode.NONE, cmac );
		return cmac;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * 3.2  Local Cryptogram
	 * IAD-MAC = Leftmost 8 bytes of AES-CMAC+ (SKi) [0000 || Input Data] 
	 */
	public static Binary calcIadMac( AES aesSKi, Binary inputData )
	{
		Binary b = Bin( 2 ).add( inputData );
		Binary cmac = calcAesCmacPlus( aesSKi, b );
		return cmac.first( 8 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Calc IAD-MAC. Book E, 3.2  Local Cryptogram.
	 * Input data:
	 *  • PDOL Values (Value field of PDOL Related Data)
	 *  • CDOL1 Related Data
	 *  • (optional) Terminal Relay Resistance Entropy
	 *  • (optional) Last ERRD Response (without tag '80' and length '0A')
	 *  • GENERATE AC Response Message without:
	 *       -- Application Cryptogram
	 *       -- EDA-MAC
	 *       -- Tag '77' and length
	 *  • SDA Hash (hash over the Card Static Data to be Authenticated)
	 * 
	 * IAD-MAC = Leftmost 8 bytes of AES-CMAC+ (SKi) [0000 || Input Data].
	 * @param terminalRREntropy - can be null or empty.
	 * @param lastERRDResponse
	 */
	public static Binary calcIadMac( AES aesSKi, final Binary PDOLValues, final Binary CDOL1RelatedData,
			final Binary terminalRREntropy, final Binary lastERRDResponse,
			final Binary genAcResponse, final Binary sdaHash )
	{
		Binary data = Bin().reserve( 300 );
		data.add( PDOLValues );
		data.add( CDOL1RelatedData );
		if( terminalRREntropy != null )
			data.add( terminalRREntropy );
		if( lastERRDResponse != null )
			data.add( lastERRDResponse );
		data.add( genAcResponse );
		data.add( sdaHash );

		Binary iadMac = calcIadMac( aesSKi, data );
		return iadMac;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Calc EDA-MAC. Book E, 3.2  Local Cryptogram.
	 */
	//EDA-MAC = Leftmost 8 bytes of AES-CMAC (SKi) ['0000' || AC || IAD-MAC]
	public static Binary calcEdaMac( AES aesSKi, final Binary ac, final Binary iadMac )
	{
		Binary data = Bin( 2 ).add( ac ).add( iadMac );
		Binary edaMac = aesSKi.calcCMAC( data, null ).first( 8 );
		return edaMac;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Calc EMV session key.
	 * @param MK - card key - DES2_EDE or AES
	 * @param R - данные для диверсификации [ blockSize байт ].
	 * @return session key - размер равен размеру MK.
	 */
	public static Binary calcEmvSessionKey( final ABlockCipher MK, final Binary R )
	{
		MUST( R.size() == MK.getBlockSize(), "Wrong R size for EMV session key" );

		if( (MK instanceof AES) && (MK.getKeySize() == 16) )
		{
			Binary sk = R.clone();
			MK.encryptBlock( sk );
			return sk;
		}

		Binary l = R.clone();
		l.set( 2, 0xF0 );
		Binary r = R.clone();
		r.set( 2, 0x0F );

		Binary sk = MK.encrypt( Bin( l, r ), CryptoMode.ECB, AlignMode.NONE ).first( MK.getKeySize() );
		return sk;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Calc card session key for AC.
	 * Book E, 4.2  Application Cryptogram
	 * @param MKac - Ключ карты для вычисления криптограмм DES2_EDE или AES.
	 * @param atc - Счётчик криптограмм карты (EMV тег - 0x9F36) [2 байта].
	 * @return SKac
	 */
	public static Binary calcEmvSessionKeyAC( final ABlockCipher MKac, final Binary atc )
	{
		MUST( atc.size() == 2, "Wrong ATC size" );
		Binary R = atc.clone();
		R.resize( MKac.getBlockSize() );
		Binary SKac = calcEmvSessionKey( MKac, R );
		return SKac;
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static Binary calcEmvSessionKeyAC( final ABlockCipher MKac, int atc )
	{
		MUST( Int.isU16( atc ), "Wrong ATC" );
		return calcEmvSessionKeyAC( MKac, Bin().addU16( atc ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сгенерировать сессионный ключ SKac для вычисления криптограмм.
	 * @param kdm - Алгоритм вывода сессионного ключа, см. SKDerivationMethod.
	 * @param MKac - Ключ карты для вычисления криптограмм [16 байт].
	 * @param atc - Счётчик криптограмм карты (EMV тег - 0x9F36) [2 байта].
	 * @param unpredictableNumber - Случайное число терминала [4 байта],
	 * не используется в EMV, нужно в MChip. (EMV тег - 0x9F37) ( default = Bin() ).
	 * @return [16 байт] Сессионный ключ SKac. 
	 */
	public static Binary calc3DESSessionKeyAC( int kdm, DES2_EDE MKac, final Binary atc, 
		final Binary unpredictableNumber )
	{
		if( kdm == SKDerivationMethod.MCHIP )
		{
			MUST( atc.size() == 2, "Wrong ATC size" );
			MUST( unpredictableNumber.size() == 4, "Wrong unpredictableNumber size" );

			Binary R = atc.clone();
			R.resize( 4 );
			R.add( unpredictableNumber );
			Binary SKac = calcEmvSessionKey( MKac, R );
			return SKac;
		}
		else
		{
			return calcEmvSessionKeyAC( MKac, atc );
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Calc card AC for 3DES alg
	 * Book E, 4.2  Application Cryptogram
	 * @return ac
	 */
	public static Binary calcAC( DES2_EDE SKac, final Binary inputData )
	{
		Binary ac = SKac.calcCCS( inputData, AlignMode.BLOCK, CCSMode.FAST );
		return ac;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Calc card AC for AES
	 * Book E, 4.2  Application Cryptogram
	 */
	public static Binary calcAC( AES SKac, final Binary inputData )
	{
		Binary ac = SKac.calcCMAC( inputData, null ).first( 8 );
		return ac;
	}

	// =================================================================================================================
	// Data Storage
	// =================================================================================================================

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Зашифровать Data Envelope + MAC.
	 * Формирование ответа карты на READ DATA.
	 */
	public static Binary encryptReadData( AES aesSKc, AES aesSKi, Int CMC, final Binary plainTlv )
	{
		Binary encryptedTLV = cryptAesCTR( aesSKc, new Int( CMC.val ), plainTlv );
		Binary mac = calcAesMac( aesSKi, CMC, encryptedTLV );
		return encryptedTLV.add( mac );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Расшифровать ответ карты на READ DATA.
	 * @return Plain TLV или null, если MAC не совпал.
	 */
	public static Binary decryptReadData( AES aesSKc, AES aesSKi, Int CMC, final Binary crypt )
	{
		if( crypt.size() < 8 )
			return null;

		Binary cardMac = crypt.last( 8 );
		Binary encryptedTLV = crypt.first( crypt.size() - 8 );

		// CMC для MAC и Decrypt один и тот же
		Binary myMac = calcAesMac( aesSKi, new Int( CMC.val ), encryptedTLV );
		if( !myMac.equals( cardMac ) )
			return null;

		Binary plainTLV = cryptAesCTR( aesSKc, CMC, encryptedTLV );
		return plainTLV;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Зашифровать/Расшифровать Data Envelope для отправки в карту в команде WRITE DATA.
	 */
	public static Binary cryptWriteData( AES aesSKc, Int KMC, final Binary plainTlv )
	{
		return cryptAesCTR( aesSKc, KMC, plainTlv );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вычислить MAC от Plaint TLV  Data Envelope для ответа карты на WRITE DATA
	 */
	public static Binary calcDataEnvelopeMac( AES aesSKi, Int CMC, final Binary plainTlv )
	{
		return calcAesMac( aesSKi, CMC, plainTlv );
	}

	// =================================================================================================================

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @param sdaRecords Все записи, участвующие в SDA.
	 * @param конкатенация всех TLV из списка 'Extended SDA Tag List'.
	 * @param AIP [2 байта] без тега
	 * @return
	 */
	public static Binary calcSDAHash( IHash hashAlg, final Binary sdaRecords, Binary extendedSDARelData, final Binary AIP )
	{
		return hashAlg.calc( Bin().add( sdaRecords ).add( extendedSDARelData ).add( AIP ) );
	}

}
