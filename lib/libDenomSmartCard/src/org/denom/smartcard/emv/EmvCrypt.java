// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.emv;

import org.denom.*;
import org.denom.crypt.*;
import org.denom.crypt.ec.ECAlg;

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
	 * Book E,  8.6.2  AES-CTR.
	 * @param messageCounter (U16)
	 * @param data input message (plain or crypt).
	 * @return output message C (crypt or plain).
	 */
	public static Binary cryptAesCTR( AES aes, int messageCounter, final Binary data )
	{
		MUST( Int.isU16( messageCounter ), "Wrong messageCounter for AES-CTR" );
		Binary SV = Bin( aes.getBlockSize() );
		SV.setU16( 0, messageCounter );
		Binary C = aes.cryptCTR( data, SV );
		return C;
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
}
