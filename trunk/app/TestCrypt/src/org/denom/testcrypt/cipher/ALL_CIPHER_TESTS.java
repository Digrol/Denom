package org.denom.testcrypt.cipher;

public class ALL_CIPHER_TESTS
{
	public static void main( String[] args )
	{
		new TestRC4();
		new TestRC5();
		new TestRC6();
		new TestARIA();

		new TestSerpent();
		new TestTnepres();

		new TestCamellia();
		new TestBlowfish();
		new TestTwofish();
		new TestThreefish();

		new TestCAST5();
		new TestCAST6();

		new TestIDEA();
		new TestXTEA();
		new TestSEED();
		new TestSalsa20();
		new TestXSalsa20();
		new TestChaCha();
		new TestHC();
		new TestISAAC();
		new TestShacal2();

		new TestGOST28147();
		new TestGOST3412();
	}
}
