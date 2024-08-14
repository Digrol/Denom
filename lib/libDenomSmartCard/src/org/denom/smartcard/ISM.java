// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard;

/**
 * Интерфейс для Secure Messaging.
 */
public interface ISM
{
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Зашифровать командное APDU.
	 * @param capduNoSM - Исходное командное APDU без SM
	 * @return Сформированное командное APDU с SM
	 */
	public CApdu encryptCommand( final CApdu capduNoSM );

	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Расшифровать ответное APDU с SM.
	 * @param rapduWithSM - Ответное APDU с SM.
	 * @return Ответное APDU без SM.
	 */
	public RApdu decryptResponse( final RApdu rapduWithSM );
}
