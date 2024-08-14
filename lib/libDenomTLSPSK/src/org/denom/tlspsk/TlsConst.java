// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.tlspsk;

public abstract class TlsConst
{

	public static class ContentType
	{
		public static final short CHANGE_CIPHER    = 0x14;
		public static final short ALERT            = 0x15;
		public static final short HANDSHAKE        = 0x16;
		public static final short APPLICATION_DATA = 0x17;
	}


	public static class Protocol
	{
		public static final int TLSv1_0 = 0x0301;
		public static final int TLSv1_1 = 0x0302;
		public static final int TLSv1_2 = 0x0303;

		public static String toStr( int protocol )
		{
			switch( protocol )
			{
				case TLSv1_0: return "TLS 1.0";
				case TLSv1_1: return "TLS 1.1";
				case TLSv1_2: return "TLS 1.2";
				default: return "";
			}
		}
	}


	public static class HandshakeType
	{
		public static final int CLIENT_HELLO        =  1; // 01
		public static final int SERVER_HELLO        =  2; // 02
		public static final int SERVER_KEY_EXCHANGE = 12; // 0C
		public static final int SERVER_HELLO_DONE   = 14; // 0E
		public static final int CLIENT_KEY_EXCHANGE = 16; // 10
		public static final int FINISHED            = 20; // 14

		public static String toStr( int type )
		{
			switch( type )
			{
				case CLIENT_HELLO:        return "client_hello";
				case SERVER_HELLO:        return "server_hello";
				case SERVER_KEY_EXCHANGE: return "server_key_exchange";
				case SERVER_HELLO_DONE:   return "server_hello_done";
				case CLIENT_KEY_EXCHANGE: return "client_key_exchange";
				case FINISHED:            return "finished";
				default: return "";
			}
		}
	}


	public static class CipherSuite
	{
		public static final int PSK_NULL_SHA           = 0x002C;
		public static final int PSK_3DES_EDE_CBC_SHA   = 0x008B;
		public static final int PSK_AES_128_CBC_SHA    = 0x008C;
		public static final int PSK_AES_128_CBC_SHA256 = 0x00AE;
		public static final int PSK_NULL_SHA256        = 0x00B0;

		public static String toStr( int cipherSuite )
		{
			switch( cipherSuite )
			{
				case PSK_NULL_SHA:           return "PSK_WITH_NULL_SHA";
				case PSK_3DES_EDE_CBC_SHA:   return "PSK_WITH_3DES_EDE_CBC_SHA";
				case PSK_AES_128_CBC_SHA:    return "PSK_WITH_AES_128_CBC_SHA";
				case PSK_AES_128_CBC_SHA256: return "PSK_WITH_AES_128_CBC_SHA256";
				case PSK_NULL_SHA256:        return "PSK_WITH_NULL_SHA256";
				default: return "";
			}
		}
	}


	public static class Extension
	{
		// RFC 2546
		public static final int MAX_FRAGMENT_LENGTH = 1; // 0001
		public static final int TRUNCATED_HMAC = 4;      // 0004
		// RFC 7366
		public static final int ENCRYPT_THEN_MAC = 22;   // 0016

		public static String toStr( int extensionType )
		{
			switch( extensionType )
			{
				case MAX_FRAGMENT_LENGTH: return "max_fragment_length";
				case TRUNCATED_HMAC:      return "truncated_hmac";
				case ENCRYPT_THEN_MAC:    return "encrypt_then_mac";
				default: return "";
			}
		}
	}


	public static class Alert
	{
		public static final int CLOSE_NOTIFY          = 0;
		public static final int UNEXPECTED_MESSAGE    = 10;
		public static final int BAD_RECORD_MAC        = 20;
		public static final int RECORD_OVERFLOW       = 22;
		public static final int HANDSHAKE_FAILURE     = 40;
		public static final int ILLEGAL_PARAMETER     = 47;
		public static final int DECODE_ERROR          = 50;
		public static final int DECRYPT_ERROR         = 51;
		public static final int PROTOCOL_VERSION      = 70;
		public static final int INTERNAL_ERROR        = 80;
		public static final int UNSUPPORTED_EXTENSION = 110;

		public static String toStr( int alert )
		{
			switch( alert )
			{
				case CLOSE_NOTIFY:          return "close_notify";
				case UNEXPECTED_MESSAGE:    return "unexpected_message";
				case BAD_RECORD_MAC:        return "bad_record_mac";
				case RECORD_OVERFLOW:       return "record_overflow";
				case HANDSHAKE_FAILURE:     return "handshake_failure";
				case ILLEGAL_PARAMETER:     return "illegal_parameter";
				case DECODE_ERROR:          return "decode_error";
				case DECRYPT_ERROR:         return "decrypt_error";
				case PROTOCOL_VERSION:      return "protocol_version";
				case INTERNAL_ERROR:        return "internal_error";
				case UNSUPPORTED_EXTENSION: return "unsupported_extension";
				default: return "";
			}
		}
	}

}
