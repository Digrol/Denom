// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.smartcard.gp;

import org.denom.Binary;
import org.denom.smartcard.ISecurityModuleBase;

/**
 * Выработка сессионных ключей для домена GP.
 */
public interface ISecurityModuleGP extends ISecurityModuleBase
{
	// -----------------------------------------------------------------------------------------------------------------
	/**
	 * Сгенерировать сессионные ключи для SM с приложением GP Security Domain.
	 * Схема диверсификации ключей определяется автоматически.
	 * Генерирует исключение в случае неудачной проверки криптограммы карты.
	 * @param smMode - режим SM [1 байт].
	 * @param hostChallenge - Случайное число терминала [8 байт].
	 * @param initUpdateResponse - Ответ приложения на команду GP_INITIALIZE_UPDATE [28 байт].
	 * @return конкатенация:<br>
	 *   – сессионный ключ шифрования          (KEY ENC) [16 байт];<br>
	 *   – сессионный ключ для вычисления CMAC (KEY CMAC) [16 байт];<br>
	 *   – сессионный ключ для вычисления RMAC (KEY RMAC) [16 байт];<br>
	 *   – сессионный ключ шифрования ключей   (KEY DEK)  [16 байт];<br>
	 *   – криптограмма терминала ICV [8 байт];<br>
	 *   – команда GP EXTERNAL AUTHENTICATE целиком [21 байт]: APDU header [5] + ICV [8] + MAC[8].
	 */
	public Binary gpGenSmSessionKeys( int smMode, Binary hostChallenge, Binary initUpdateResponse );

}
