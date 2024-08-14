// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.crypt;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.denom.*;
import org.denom.format.*;
import org.denom.crypt.hash.IHash;

import static org.denom.Binary.*;
import static org.denom.format.BerTLV.Tlv;
import static org.denom.Ex.*;

// -----------------------------------------------------------------------------------------------------------------
/**
 * Асимметричный криптографический алгоритм RSA (RFC 3447).
 */
public class RSA implements IBinable, Cloneable
{
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Ключи не заданы, можно сгенерировать методом Generate или задать методами Set*.
	 */
	public RSA()
	{
		clear();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Открытая часть ключа.
	 * @param n - модуль.
	 * @param e - открытая экспонента, обычно "03" или "010001".
	 */
	public RSA( final Binary n, final Binary e )
	{
		setPublic( n, e );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Конструктор, секретная часть.
	 * @param n - модуль.
	 * @param d - секретная экспонента.
	 */
	public RSA( final Binary n, final Binary d, int dummy )
	{
		setPrivate( n, d );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Конструктор, секретная и открытая часть.
	 * @param n - модуль.
	 * @param e - открытая экспонента, обычно "03" или "010001".
	 * @param d - секретная экспонента.
	 */
	public RSA( final Binary n, final Binary e, final Binary d )
	{
		setNED( n, e, d );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Конструктор, ключи в формате CRT.
	 * @param p  - первое простое число.
	 * @param q  - второе простое число.
	 * @param dp - D mod (P-1).
	 * @param dq - D mod (Q-1).
	 * @param qp - Q^-1 mod P.
	 */
	public RSA( final Binary p, final Binary q, final Binary dp, final Binary dq, final Binary qp )
	{
		clear();
		setPrivateCRT( p, q, dp, dq, qp );
	}

	// -----------------------------------------------------------------------------------------------------------------
	@Override
	public RSA clone()
	{
		RSA r = new RSA();
		r.NLen = this.NLen;
		r.N = new BigInteger( this.N.toByteArray() );
		r.E = new BigInteger( this.E.toByteArray() );
		r.D = new BigInteger( this.D.toByteArray() );

		r.P  = new BigInteger( this.P.toByteArray() );
		r.Q  = new BigInteger( this.Q.toByteArray() );
		r.DP = new BigInteger( this.DP.toByteArray() );
		r.DQ = new BigInteger( this.DQ.toByteArray() );
		r.QP = new BigInteger( this.QP.toByteArray() );
		return r;
	}
	
	// =================================================================================================================
	/// Работа с ключами
	// =================================================================================================================

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return - true, если есть компоненты открытого ключа
	 */
	public boolean isPublic()
	{
		return !E.equals( BigInteger.ZERO );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return - true, если есть компоненты секретного ключа.
	 */
	public boolean isPrivate()
	{
		return !D.equals( BigInteger.ZERO );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * @return - true, если есть компоненты секретного ключа в формате CRT.
	 */
	public boolean isPrivateCRT()
	{
		return !P.equals( BigInteger.ZERO );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Возвращает длину модуля в байтах
	 */
	public int getNLen()
	{
		return NLen;
	}
	
	// -----------------------------------------------------------------------------------------------------------------
	public Binary getN()
	{
		return BigInt_Binary( N, 0 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary getE()
	{
		return BigInt_Binary( E, 0 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary getD()
	{
		return BigInt_Binary( D, NLen );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary getP()
	{
		return BigInt_Binary( P, NLen >>> 1 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary getQ()
	{
		return BigInt_Binary( Q, NLen >>> 1 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary getDP()
	{
		return BigInt_Binary( DP, NLen >>> 1 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary getDQ()
	{
		return BigInt_Binary( DQ, NLen >>> 1 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public Binary getQP()
	{
		return BigInt_Binary( QP, NLen >>> 1 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать ключ: только открытая часть.
	 * @param n - модуль.
	 * @param e - открытая экспонента, обычно "03" или "010001".
	 */
	public void setPublic( final Binary n, final Binary e )
	{
		clear();
		N = Binary_BigInt( n );
		NLen = n.size();
		E = Binary_BigInt( e );
		MUST( !n.empty() && !e.empty() && checkNE(), "Некорректный открытый ключ RSA" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать ключ: секретная часть.
	 * @param n - модуль.
	 * @param d - секретная экспонента.
	 */
	public void setPrivate( final Binary n, final Binary d )
	{
		clear();

		MUST( !n.empty() && !d.empty(), "Пустые компоненты ключа RSA" );
		N = Binary_BigInt( n );
		NLen = n.size();
		D = Binary_BigInt( d );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать ключ: секретная и открытая часть.
	 * @param n - модуль.
	 * @param e - открытая экспонента, обычно "03" или "010001".
	 * @param d - секретная экспонента.
	 */
	public void setNED( final Binary n, final Binary e, final Binary d )
	{
		clear();

		N = Binary_BigInt( n );
		NLen = n.size();
		E = Binary_BigInt( e );
		D = Binary_BigInt( d );
		MUST( !n.empty() && !e.empty() && !d.empty() && checkNE(), "Некорректный открытый ключ RSA" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать ключ в формате CRT.
	 * @param p  - первое простое число.
	 * @param q  - второе простое число.
	 * @param dp - D mod (P-1).
	 * @param dq - D mod (Q-1).
	 * @param qp - Q^-1 mod P.
	 */
	public void setPrivateCRT( final Binary p, final Binary q, final Binary dp, final Binary dq, final Binary qp )
	{
		clear();

		MUST( !p.empty() && !q.empty() && !dp.empty() && !dq.empty() && !qp.empty(), "Пустые компоненты ключа RSA" );
		P  = Binary_BigInt( p );
		Q  = Binary_BigInt( q );
		DP = Binary_BigInt( dp );
		DQ = Binary_BigInt( dq );
		QP = Binary_BigInt( qp );

		MUST( !P.equals( BigInteger.ZERO ) && !Q.equals( BigInteger.ZERO ) && !DP.equals( BigInteger.ZERO )
			&& !DQ.equals( BigInteger.ZERO ) && !QP.equals( BigInteger.ZERO ), "Нули в компонентах ключа RSA" );

		calcNED();
		MUST( checkPQ(), "Некорректный ключ RSA" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать ключ (все компоненты) в формате PKCS#8 - rfc5958, rfc3447.
	 */
	public void setPrivateKeyPKCS8( final Binary data )
	{
		clear();
		BerTLVList l = new BerTLVList( data );

		// Проверим OID == RSA OID ()
		MUST( l.find( "30/30/06" ).value.equals( RSA_OID ), "Некорректный формат ключа" );

		l.assign( l.find( "30/04" ).value ); // Все компоненты ключа
		l.assign( l.find( "30" ).value );
		MUST( l.recs.size() >= 9, "RSA ключ не в формате PKCS#8" );
		// Первая запись - версия, игнорируем
		N  = new BigInteger( l.recs.get( 1 ).value.getBytes() );
		NLen = (N.bitLength() + 7) / 8;
		E  = new BigInteger( l.recs.get( 2 ).value.getBytes() );
		D  = new BigInteger( l.recs.get( 3 ).value.getBytes() );
		P  = new BigInteger( l.recs.get( 4 ).value.getBytes() );
		Q  = new BigInteger( l.recs.get( 5 ).value.getBytes() );
		DP = new BigInteger( l.recs.get( 6 ).value.getBytes() );
		DQ = new BigInteger( l.recs.get( 7 ).value.getBytes() );
		QP = new BigInteger( l.recs.get( 8 ).value.getBytes() );

		MUST( checkPQ(), "Некорректные компоненты ключа RSA" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выгрузить ключ (все компоненты) в формате PKCS#8 - rfc5958, rfc3447.
	 */
	public Binary getPrivateKeyPKCS8()
	{
		MUST( isPrivateCRT(), "Секретные компоненты ключа не заданы" );

		// Версия и компоненты ключа
		Binary key =
			Tlv( 0x30, "" + // SEQUENCE
				Tlv( 0x02, "00" ) +// INTEGER - версия
				Tlv( 0x02, Bin(  N.toByteArray() ) ) +
				Tlv( 0x02, Bin(  E.toByteArray() ) ) +
				Tlv( 0x02, Bin(  D.toByteArray() ) ) +
				Tlv( 0x02, Bin(  P.toByteArray() ) ) +
				Tlv( 0x02, Bin(  Q.toByteArray() ) ) +
				Tlv( 0x02, Bin( DP.toByteArray() ) ) +
				Tlv( 0x02, Bin( DQ.toByteArray() ) ) +
				Tlv( 0x02, Bin( QP.toByteArray() ) )
			);

		// Контейнер с ключом
		Binary res =
			Tlv( 0x30, "" +
				Tlv( 0x02, "00" ) +
				Tlv( 0x30, "" + Tlv( 0x06, RSA_OID ) + Tlv( 0x05, "" ) ) +
				Tlv( 0x04, key )
			);

		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Задать открытый ключ (только N, E) в формате X.509 - rfc5958, rfc3447.
	 * Формат легко понять по getPublicKeyX509.
	 */
	public void setPublicKeyX509( final Binary data )
	{
		clear();
		BerTLVList l = new BerTLVList( data );

		// Проверим OID == RSA OID
		MUST( l.find( "30/30/06" ).value.equals( RSA_OID ), "Некорректный формат ключа" );

		Binary bin = l.find( "30/03" ).value; // Открытые компоненты ключа ( N, E ).

		MUST( bin.size() > 1, "Некорректный формат ключа" );
		bin = bin.slice( 1, bin.size() - 1 );
		l.assign( bin );

		l.assign( l.find( "30" ).value );

		MUST( l.recs.size() >= 2, "RSA ключ не в формате X.509" );
		N = new BigInteger( l.recs.get( 0 ).value.getBytes() );
		NLen = (N.bitLength() + 7) / 8;
		E = new BigInteger( l.recs.get( 1 ).value.getBytes() );

		MUST( checkNE(), "Некорректные компоненты ключа RSA" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Выгрузить открытый ключ (только N, E) в формате X509 - rfc5958, rfc3447.
	 */
	public Binary getPublicKeyX509()
	{
		MUST( isPublic(), "Компоненты ключа не заданы" );

		Binary key = 
			Tlv( 0x30, ""
				+ Tlv( 0x02, Bin( N.toByteArray() ) )
				+ Tlv( 0x02, Bin( E.toByteArray() ) ) );

		// Контейнер с ключом
		Binary res =
			Tlv( 0x30, ""
				+ Tlv( 0x30, "" + Tlv( 0x06, RSA_OID ) + Tlv( 0x05, "" ) )
				+ Tlv( 0x03, "00" + key ) );

		return res;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Serialize key components according to 'Denom Structured Data Standard'.
	 * If key component absent, then stored empty array.
	 * 
	 * struct RSA
	 * {
	 *     // Module size in bytes.
	 *     int NLen;
	 *
	 *     // CRT components
	 *     Binary p;
	 *     Binary q;
	 *     Binary dp;
	 *     Binary dq;
	 *     Binary qp;
	 *
	 *     // Plain components
	 *     Binary n;
	 *     Binary e;
	 *     Binary d;
	 * }
	 */
	@Override
	public Binary toBin()
	{
		Binary emptyBin = Bin();
		BinBuilder bb = new BinBuilder();
		bb.append( NLen );

		if( isPrivateCRT() )
		{
			bb.append( getP() );
			bb.append( getQ() );
			bb.append( getDP() );
			bb.append( getDQ() );
			bb.append( getQP() );
		}
		else
		{
			for( int i = 0; i < 5; ++i )
				bb.append( emptyBin );
		}

		bb.append( isPublic() ? getN() : emptyBin );
		bb.append( isPublic() ? BigInt_Binary( E, 4 ) : emptyBin );
		bb.append( isPrivate() ? getD() : emptyBin );
		return bb.getResult();
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Считать сериализованные компоненты RSA-ключа, структуру см. в toBin().
	 */
	@Override
	public RSA fromBin( final Binary bin, int offset )
	{
		BinParser parser = new BinParser( bin, offset );

		int len = parser.getInt();
		MUST( (len >= 0) && (len <= 0x10000 ), "Binarization: Wrong data for parsing as RSA object" );
		NLen = len;

		int halfLen = NLen >> 1;

		Binary p = parser.getBinary( halfLen );
		Binary q = parser.getBinary( halfLen );
		Binary dp = parser.getBinary( halfLen );
		Binary dq = parser.getBinary( halfLen );
		Binary qp = parser.getBinary( halfLen );

		Binary n = parser.getBinary( NLen );
		Binary e = parser.getBinary( NLen );
		Binary d = parser.getBinary( NLen );

		if( !p.empty() && !q.empty() && !dp.empty() && !dq.empty() && !qp.empty() )
		{
			setPrivateCRT( p, q, dp, dq, qp );
			return this;
		}

		if( !n.empty() && !d.empty() && !e.empty() )
		{
			setNED( n, e, d );
			return this;
		}

		if( !n.empty() && !d.empty() )
		{
			setPrivate( n, d );
			return this;
		}

		if( !n.empty() && !e.empty() )
		{
			setPublic( n, e );
		}

		return this;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Считать сериализованные компоненты RSA-ключа, структуру см. в toBin().
	 */
	@Override
	public RSA fromBin( final Binary bin )
	{
		return this.fromBin( bin, 0 );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сериализовать в JSON.
	 * Выгружаются все компоненты в HEX-виде.
	 */
	public JSONObject toJSON()
	{
		JSONObject jo = new JSONObject();
		if( isPrivateCRT() )
		{
			jo.put( "P", getP().Hex() );
			jo.put( "Q", getQ().Hex() );
			jo.put( "DP", getDP().Hex() );
			jo.put( "DQ", getDQ().Hex() );
			jo.put( "QP", getQP().Hex() );
		}
		if( isPrivate() )
		{
			jo.put( "D", getD().Hex() );
		}
		if( isPublic() )
		{
			jo.put( "N", getN().Hex() );
			jo.put( "E", getE().Hex() );
		}
		return jo;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Считать сериализованный ключ из JSON-объекта.
	 * @return true - ключ успешно считан, иначе false.
	 */
	public void fromJSON( JSONObject jo )
	{
		Binary p = Bin( jo.optString( "P" ) );

		if( !p.empty() )
		{
			Binary q = Bin( jo.getString( "Q" ) );
			Binary dp = Bin( jo.getString( "DP" ) );
			Binary dq = Bin( jo.getString( "DQ" ) );
			Binary qp = Bin( jo.getString( "QP" ) );
			setPrivateCRT( p, q, dp, dq, qp );
		}
		else
		{
			Binary n = Bin( jo.optString( "N" ) );
			Binary e = Bin( jo.optString( "E" ) );
			Binary d = Bin( jo.optString( "D" ) );
			if( !d.empty() && !e.empty() )
			{
				setNED( n, e, d );
			}
			else if( !d.empty() )
			{
				setPrivate( n, d );
			}
			else
			{
				setPublic( n, e );
			}
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Считать сериализованный ключ из JSON-объекта.
	 * @return true - ключ успешно считан, иначе false.
	 */
	public void fromJSON( String serialized )
	{
		fromJSON( new JSONObject( serialized ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сгенерировать ключевую пару.
	 * @param keyLenBits - размер модуля в битах (кратно 8).
	 * @param e - открытая экспонента.
	 * @return - ссылка на себя.
	 */
	public RSA generateKeyPair( int keyLenBits, final Binary e )
	{
		clear();

		initSecureRandom();

		// Найти простые числа p и q, чтобы q < p  и  GCD( E, (p-1)*(q-1) ) == 1
		E = Binary_BigInt( e );

		BigInteger p1 = null;
		BigInteger q1 = null;
		BigInteger h = null;
		boolean good = false;
		do
		{
			P = BigInteger.probablePrime( (keyLenBits + 1) >>> 1, randSecure );
			Q = BigInteger.probablePrime( (keyLenBits + 1) >>> 1, randSecure );

			if( P.compareTo( Q ) == -1 )
			{
				BigInteger t = P;
				P = Q;
				Q = t;
			}

			if( P.compareTo( Q ) == 0 )
				continue;

			N = P.multiply( Q );
			if( N.bitLength() != keyLenBits )
			{
				continue;
			}

			p1 = P.subtract( BigInteger.ONE );
			q1 = Q.subtract( BigInteger.ONE );
			h = p1.multiply( q1 );
			good = E.gcd( h ).compareTo( BigInteger.ONE ) == 0;
		}
		while( !good );

		// D  = E^-1 mod ((P-1)*(Q-1))
		// DP = D mod (P - 1)
		// DQ = D mod (Q - 1)
		// QP = Q^-1 mod P
		D = E.modInverse( h );
		DP = D.mod( p1 );
		DQ = D.mod( q1 );
		QP = Q.modInverse( P );

		NLen = keyLenBits >> 3;
		
		return this;
	}

	// =================================================================================================================
	/// Базовые преобразования RSA
	// =================================================================================================================
	
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Преобразование данных на основе модуля и открытой экспоненты.
	 * Криптографическое преобразование на открытом ключе.
	 * Данные не выравниваются, размер данных должен быть равен размеру модуля ( N ),
	 * Данные интерпретируются как большое целое число, причём это число должно быть арифметически меньше N.
	 */
	public Binary cryptPublic( Binary inputData )
	{
		MUST( isPublic(), "Открытый ключ для RSA не задан" );
		MUST( inputData.size() == NLen, "Размер данных для RSA должен совпадать с размером модуля (N)" );

		BigInteger data = Binary_BigInt( inputData );
		MUST( data.compareTo( N ) == -1, "Данные для RSA должны быть меньше модуля (N)" );

		BigInteger res = data.modPow( E, N );
		return BigInt_Binary( res, NLen );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Криптографическое преобразование на секретном ключе.
	 * Требования к данным - см. CryptPublic.
	 */
	public Binary cryptPrivate( Binary inputData )
	{
		MUST( isPrivate(), "Секретный ключ для RSA не задан" );
		MUST( inputData.size() == NLen, "Размер данных для RSA должен совпадать с размером модуля (N)" );

		BigInteger data = Binary_BigInt( inputData );
		MUST( data.compareTo( N ) == -1, "Данные для RSA должны быть меньше модуля (N)" );

		BigInteger res;

		if( P.equals( BigInteger.ZERO ) )
		{
			res = data.modPow( D, N );
		}
		else
		{	// По Китайской теореме об остатках
			// T1 = data ^ DP mod P
			// T2 = data ^ DQ mod Q
			BigInteger T1 = data.modPow( DP, P );
			BigInteger T2 = data.modPow( DQ, Q );

			// T1 = (T1 - T2) * (Q^-1 mod P) mod P
			T1 = T1.subtract( T2 ).multiply( QP ).mod( P );
			// res = T1 * Q + T2 
			res = T1.multiply( Q ).add( T2 );
		}

		return BigInt_Binary( res, NLen );
	}

	// =================================================================================================================
	/// Схема шифрования PKCS#1 v1.5.
	// =================================================================================================================

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Шифрование данных открытым ключом по схеме - RSAES-PKCS1-V1_5-ENCRYPT - rfc3447, секция 7.2.1.
	 * @param data - Длина данных должна удовлетворять условию: len <= Nlen - 11.
	 * @return - Криптограмма.
	 */
	public Binary encryptPublicPKCS1v1_5( final Binary data )
	{
		MUST( isPublic(), "Открытый ключ для RSA не задан" );

		int k = getNLen();
		MUST( data.size() <= (k - 11), "Данные для шифрования RSA должны быть короче Модуля (N) как минимум на 11 байт" );

		initSecureRandom();

		Binary padded = Bin();
		padded.reserve( k );
		padded.add( 0x00 );
		padded.add( 0x02 );
		// Случайные ненулевые байты
		int r_size = k - data.size() - 3;
		for( int i = 0; i < r_size; ++i )
		{
			padded.add( randSecure.nextInt( 255 ) + 1 );
		}
		padded.add( 0x00 );
		padded.add( data );

		return cryptPublic( padded );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Расшифрование данных секретным ключом по схеме - RSAES-PKCS1-V1_5-DECRYPT - rfc3447, секция 7.2.2.
	 * @param crypt - криптограмма, полученная с помощью открытого ключа, длина = длине модуля.
	 * @return - Расшифрованные данные.
	 */
	public Binary decryptPrivatePKCS1v1_5( final Binary crypt )
	{
		Binary padded = cryptPrivate( crypt );

		MUST( (padded.get( 0 ) == 0x00) && (padded.get( 1 ) == 0x02), "Некорректная криптограмма RSA" );

		// Пропускаем случайные байты
		int i = 2;
		while( (i < padded.size()) && (padded.get( i ) != 0) )
		{
			++i; // Пропускаем случайные байты
		}
		++i; // нулевой байт - терминатор случайной последовательности
		MUST( (i > 10) && (i <= padded.size()), "Некорректная криптограмма RSA" );

		return padded.slice( i, padded.size() - i );
	}

	// =================================================================================================================
	/// Схема подписывания PKCS#1 v1.5.
	// =================================================================================================================

	// -----------------------------------------------------------------------------------------------------------------
	// Получаем OID по размеру хеша
	private static String getHashOID( int hashSize )
	{
		switch( hashSize )
		{
			case 0x10: return "30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 05 05 00 04 10";    // MD5
			case 0x14: return "30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14";             // SHA-1
			case 0x20: return "30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20"; // SHA-256
			case 0x30: return "30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30"; // SHA-384
			case 0x40: return "30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40"; // SHA-512
			default:   THROW( "Неподдерживаемый размер хеша" );
		}
		return "";
	}

	// -----------------------------------------------------------------------------------------------------------------
	private Binary padHashPKCS1v1_5( final Binary hash )
	{
		MUST( !hash.empty(), "Пустой хеш" );

		int Nlen = getNLen();

		Binary T = Bin( getHashOID( hash.size() ) + hash );
		MUST( (T.size() + 11) <= Nlen, "Для подписи требуется ключ большего размера" );

		Binary padded = Bin();
		padded.reserve( Nlen );
		padded.add( 0x00 );
		padded.add( 0x01 );
		padded.add( Bin( Nlen - T.size() - 3, 0xFF ) );
		padded.add( 0x00 );
		padded.add( T );

		return padded;
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Вычислить подпись (требуется секретный ключ) по схеме RSASSA-PKCS1-v1_5 - rfc3447, секция 8.2.1, 9.2.
	 * @param hash - Хеш от данных, которые требуется подписать.
	 * Параметры хеш-функции определяются по размеру хеша.
	 * @return - подпись (DS).
	 */
	public Binary calcSignPKCS1v1_5( final Binary hash )
	{
		MUST( isPrivate(), "Секретный ключ для RSA не задан" );
		return cryptPrivate( padHashPKCS1v1_5( hash ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Проверить подпись (требуется открытый ключ) по схеме RSASSA-PKCS1-v1_5 - rfc3447, секция 8.2.2, 9.2.
	 * @param hash - Хеш от данных, для которого вычислялась подпись.
	 * Параметры хеш-функции определяются по размеру хеша.
	 * @param sign - подпись (DS).
	 * @return - true, если подпись валидна.
	 */
	public boolean verifySignPKCS1v1_5( final Binary hash, final Binary sign )
	{
		MUST( isPublic(), "Открытый ключ для RSA не задан" );
		MUST( !hash.empty() && !sign.empty(), "Пустые данные" );
		return cryptPublic( sign ).equals( padHashPKCS1v1_5( hash ) );
	}
	
	// =================================================================================================================
	/// Схема шифрования OAEP.
	// =================================================================================================================

	// ---------------------------------------------------------------------------------------------------------------------
	/// RFC 3447, appendix B.2.1
	private static Binary MGF1( IHash h, final Binary seed, int len )
	{
		Binary T = Bin();
		T.reserve( len );

		for( int i = 0; T.size() < len; ++i )
		{
			T.add( h.calc( Bin( seed, Num_Bin( i, 4 ) ) ) );
		}
		return T.slice( 0, len );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Шифрование данных открытым ключом по схеме - RSAES-OAEP-ENCRYPT - rfc3447, секция 7.1.1.
	 * @param data - данные для шифрования.
	 * Длина данных должна удовлетворять условию: len <= Nlen - 2 * hashSize - 2.
	 * @param h - алгоритм хеширования.
	 * @param label - опциональные данные, могут быть пустыми или null.
	 * MGF = MGF1.
	 * @return - криптограмма, размером NLen
	 */
	public Binary encryptPublicOAEP( final Binary data, IHash h, Binary label )
	{
		MUST( isPublic(), "Открытый ключ для RSA не задан" );
		if( label == null )
			label = Bin();

		int k = getNLen();
		int hLen = h.size();
		MUST( data.size() <= (k - 2 * hLen - 2), "Данные для шифрования RSA должны быть короче" );

		// 2.b
		Binary PS = Bin( k - data.size() - 2 * hLen - 2 );
		// 2.c
		Binary DB = h.calc( label ).add( PS ).add( 0x01 ).add( data );
		// 2.d
		Binary seed = Bin().random( hLen );
		// 2.e, 2.f
		Binary maskedDB = xor( DB, MGF1( h, seed, k - hLen - 1 ) );
		// 2.g, 2.h
		Binary maskedSeed = xor( seed, MGF1( h, maskedDB, hLen ) );
		// 2.i
		Binary EM = Bin("00").add( maskedSeed ).add( maskedDB );

		return cryptPublic( EM );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Расшифрование данных секретным ключом по схеме - RSAES-OAEP-DECRYPT - rfc3447, секция 7.1.2.
	 * @param h - алгоритм хеширования.
	 * @param label - опциональные данные, могут быть пустыми или null.
	 * MGF = MGF1.
	 * @return - расшифрованные данные.
	 */
	public Binary decryptPrivateOAEP( final Binary crypt, IHash h, Binary label )
	{
		MUST( isPrivate(), "Секретный ключ для RSA не задан" );
		if( label == null )
			label = Bin();

		int k = getNLen();
		int hLen = h.size();
		Binary EM = cryptPrivate( crypt );
		MUST( EM.get( 0 ) == 0x00, "Некорректная криптограмма" );

		// 2.b
		Binary maskedSeed = EM.slice( 1, hLen );
		Binary maskedDB = EM.slice( 1 + hLen, EM.size() - 1 - hLen );

		// 2.c, 2.d
		Binary seed = xor( maskedSeed, MGF1( h, maskedDB, hLen ) );

		// 2.e, 2.f
		Binary DB = xor( maskedDB, MGF1( h, seed, k - hLen - 1 ) );

		MUST( DB.slice( 0, hLen ).equals( h.calc( label ) ), "Некорректная криптограмма" );

		// Пропускаем нулевые байты
		int i = hLen;
		while( (i < DB.size()) && (DB.get(i) == 0) )
		{
			++i; // Пропускаем нулевые байты
		}
		MUST( DB.get( i ) == 0x01, "Некорректная криптограмма" );
		++i;

		MUST( i < DB.size(), "Некорректная криптограмма RSA" );
		return DB.slice( i, DB.size() - i );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/// Вычислить подпись (требуется секретный ключ) по схеме RSASSA-PSS-SIGN - rfc3447, секция 8.1.1, 9.1.1.
	/// @param hash - Хеш от данных, которые подписываются. Вычисляется снаружи для гибкости,
	/// чтобы иметь возможность не передавать сами данные, а подписывать сразу хеш.
	/// Размер случайных данных (salt) принимается равным размеру хеша.
	public Binary calcSignPSS( final Binary hash, final IHash h )
	{
		MUST( isPrivate(), "Секретный ключ для RSA не задан" );
		MUST( hash.size() == h.size(), "Размер хеша не соответствует заданному алгоритму хеширования" );
		int k = getNLen();
		int hLen = hash.size();
		int sLen = hLen;

		MUST( k >= (hLen + sLen + 2), "Для подписывания требуется ключ большей длины" );

		// rfc3447, section 9.1.1, Step 4.
		Binary salt = Bin().random( sLen );
		// Step 5.
		Binary M_ = Bin( 8 ).add( hash ).add( salt );
		// Step 6.
		Binary H = h.calc( M_ );
		// Step 7, 8.
		Binary DB = Bin( k - sLen - hLen - 2 ).add( 0x01 ).add( salt );
		// Step 9, 10.
		Binary maskedDB = xor( DB, MGF1( h, H, k - hLen - 1 ) );
		// Step 11.
		maskedDB.set( 0, maskedDB.get( 0 ) & 0x7F );
		// Step 12.
		Binary EM = maskedDB.add( H ).add( 0xBC );
		return cryptPrivate( EM );
	}

	// -----------------------------------------------------------------------------------------------------------------
	/// Проверить подпись (требуется открытый ключ) по схеме RSASSA-PSS-VERIFY - rfc3447, секция 8.1.2, 9.1.2.
	public boolean verifySignPSS( final Binary hash, final IHash h, final Binary sign )
	{
		MUST( isPublic(), "Открытый ключ для RSA не задан" );
		MUST( !sign.empty(), "Пустые данные" );
		int k = getNLen();
		int hLen = hash.size();
		MUST( hLen == h.size(), "Размер хеша не соответствует заданному алгоритму хеширования" );

		Binary EM = cryptPublic( sign );

		// rfc3447, section 9.1.2, Step 4.
		if( EM.get( EM.size() - 1 ) != 0xBC )
			return false;

		// Step 5, 6.
		Binary maskedDB = EM.slice( 0, k - hLen - 1 );
		Binary H = EM.slice( k - hLen - 1, hLen );
		if( maskedDB.get( 0 ) >= 0x80 )
			return false;

		// Step 7, 8, 9.
		Binary DB = xor( maskedDB, MGF1( h, H, k - hLen - 1 ) );
		DB.set( 0, DB.get( 0 ) & 0x7F );
		
		// Step 10.
		// Пропускаем нулевые байты
		int i = 0;
		while( (i < DB.size()) && (DB.get( i ) == 0) )
		{
			++i; // Пропускаем нулевые байты
		}
		if( DB.get( i ) != 0x01 )
			return false;
		++i;

		// Step 11.
		Binary salt = DB.slice( i, DB.size() - i );
		// Step 12.
		Binary M_ = Bin( 8 ).add( hash).add( salt );
		// Step 13.
		Binary H_ = h.calc( M_ );
		// Step 14.
		return H.equals( H_ );
	}

	// =================================================================================================================
	// Private part
	// =================================================================================================================

	// -----------------------------------------------------------------------------------------------------------------
	private boolean checkNE()
	{
		if( N.equals( BigInteger.ZERO ) || E.equals( BigInteger.ZERO ) ) // Не равны нулю
			return false;

		if( !N.testBit( 0 ) || !E.testBit( 0 ) ) // Нечётные
			return false;

		if( N.bitLength() < 128 )
			return false;

		if( (E.bitLength() < 2) || (E.compareTo( N ) != -1) )
			return false;

		return true;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void calcNED()
	{
		N = P.multiply( Q );
		NLen = (N.bitLength() + 7) / 8;

		BigInteger p1 = P.subtract( BigInteger.ONE );
		BigInteger q1 = Q.subtract( BigInteger.ONE );

		E = DP.modInverse( p1 );

		BigInteger h = p1.multiply( q1 );
		// GCD( E, (p-1)*(q-1) ) == 1
		MUST( E.gcd( h ).compareTo( BigInteger.ONE ) == 0, "Некорректные компоненты ключа RSA" );

		// D  = E^-1 mod ((P-1)*(Q-1))
		D = E.modInverse( h );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private boolean checkPQ()
	{
		if( E.equals( BigInteger.ZERO ) || P.equals( BigInteger.ZERO )
			|| Q.equals( BigInteger.ZERO ) || D.equals( BigInteger.ZERO ) )
			return false;

		BigInteger pq = P.multiply( Q );
		if( !pq.equals( N ) )
			return false;

		BigInteger p1 = P.subtract( BigInteger.ONE );
		BigInteger q1 = Q.subtract( BigInteger.ONE );
		BigInteger h = p1.multiply( q1 );

		if( E.gcd( h ).compareTo( BigInteger.ONE ) != 0 )
			return false;

		BigInteger dp = D.mod( p1 );
		BigInteger dq = D.mod( q1 );
		BigInteger qp = Q.modInverse( P );

		if( !DP.equals( dp ) || !DQ.equals( dq ) || !QP.equals( qp ) )
			return false;

		BigInteger g1 = p1.gcd( q1 );
		BigInteger l1 = h.divide( g1 );
		if( !h.remainder( g1 ).equals( BigInteger.ZERO ) )
			return false;

		BigInteger de = D.multiply( E );
		BigInteger i = de.mod( l1 );

		return i.equals( BigInteger.ONE );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void clear()
	{
		NLen = 0;
		N = BigInteger.ZERO;
		E = BigInteger.ZERO;
		D = BigInteger.ZERO;
		P = BigInteger.ZERO;
		Q = BigInteger.ZERO;
		DP = BigInteger.ZERO;
		DQ = BigInteger.ZERO;
		QP = BigInteger.ZERO;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static BigInteger Binary_BigInt( final Binary bin )
	{
		// Первый байт может быть больше 0x7F. Чтобы число не стало отрицательным, добавляем 0 в начало.
		Binary b = new Binary( bin.size() + 1 );
		b.set( 1, bin.getDataRef(), 0, bin.size() );
		return new BigInteger( b.getDataRef() );
	}

	// -----------------------------------------------------------------------------------------------------------------
	private static Binary BigInt_Binary( final BigInteger num, int minLen )
	{
		byte[] arr = num.toByteArray();
		int offset = 0;
		if( (arr.length > 1) && (arr[0] == 0) )
			offset = 1;

		int size = arr.length - offset;
		Binary b = new Binary( ( minLen > size ) ? minLen : size );
		b.set( b.size() - size, arr, offset, size );
		return b;
	}

	// -----------------------------------------------------------------------------------------------------------------
	private void initSecureRandom()
	{
		if( this.randSecure == null )
		{
			try
			{
				this.randSecure = new SecureRandom();
			}
			catch( Throwable ex )
			{
				THROW( ex );
			}
		}
	}

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Размер модуля (N) в байтах.
	 */
	private int NLen;

	private BigInteger N;
	private BigInteger E;
	private BigInteger D;

	private BigInteger P;
	private BigInteger Q;
	private BigInteger DP;
	private BigInteger DQ;
	private BigInteger QP;

	private SecureRandom randSecure;
	
	// -----------------------------------------------------------------------------------------------------------------
	/// ASN1 OBJECT IDENTIFIER - 1.2.840.113549.1.1.1
	private static final Binary RSA_OID = new Binary( "2A 86 48 86 F7 0D 01 01 01" );
}
