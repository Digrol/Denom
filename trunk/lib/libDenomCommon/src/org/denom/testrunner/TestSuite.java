// Denom.org
// Author:  Sergey Karpov

package org.denom.testrunner;

/**
 * Интерфейс тестового сьюта.
 * В классах-наследниках все тесты (тестовые кейзы) должны быть реализованы в методах с именем case*.
 */
public interface TestSuite
{
	/**
	 * Формирование начального состояния.
	 */
	public void initState();

	/**
	 * Финализация - чистка ресурсов.
	 */
	public void finalizer();
}
