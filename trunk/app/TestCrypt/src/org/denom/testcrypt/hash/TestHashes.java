// Denom.org
// Author:  Sergey Novochenko,  Digrol@gmail.com

package org.denom.testcrypt.hash;

import org.denom.*;
import org.denom.log.*;
import org.denom.crypt.hash.*;

import static org.denom.Ex.MUST;
import static org.denom.Binary.Bin;
import static org.denom.testcrypt.hash.TestHashCommon.*;

/**
 * Test hash algorithms.
 */
class TestHashes
{
	// ILog log = new LogColoredConsoleWindow("Test Hashes");
	ILog log = new LogConsole();

	// -----------------------------------------------------------------------------------------------------------------
	TestHashes()
	{
		log.writeln( "Test hashes...\n" );

		testMD5();
		testRIPEMD160();
		testSHA1();
		testSHA224();
		testSHA256();
		testSHA384();
		testSHA512();
		testSHA512t224();
		testSHA512t256();
		testKeccak();
		testSHA3();
		testSHAKE();
		testGOST3411();

		log.writeln( "All hashes OK" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	void testMD5()
	{
		IHash alg = new MD5();
		checkMsgHash( alg, "", "d41d8cd98f00b204e9800998ecf8427e" );
		checkMsgHash( alg, "a", "0cc175b9c0f1b6a831c399e269772661" );
		checkMsgHash( alg, "abc", "900150983cd24fb0d6963f7d28e17f72" );
		checkMsgHash( alg, "abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b" );
		checkMsgHash( alg, "The quick brown fox jumps over the lazy dog", "9e107d9d372bb6826bd81d3542a419d6" );
		checkMsgHash( alg, "The quick brown fox jumps over the lazy dog.", "e4d909c290d0fb1ca068ffaddf22cbd0" );
		crossCheckStd( alg, "MD5", log );
		checkStream( alg, "MD5", log );
		compareSpeed( alg, "MD5", log );
		log.writeln( "" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	void testRIPEMD160()
	{
		IHash hash = new RIPEMD160();
		checkMsgHash( hash, "", "9c1185a5c5e9fc54612808977ee8f548b2258d31" );
		checkMsgHash( hash, "a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe" );
		checkMsgHash( hash, "abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc" );
		checkMsgHash( hash, "message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36" );
		checkMsgHash( hash, "abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc" );
		checkMsgHash( hash, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "12a053384a9c0c88e405a06c27dcf49ada62eb2b" );
		checkMsgHash( hash, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "b0e20b6e3116640286ed3a87a5713079b21f5189" );
		checkMsgHash( hash, "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "9b752e45573d4b39f4dbd3323cab82bf63326bfb" );
		check1millionA( hash, "52783243c1697bdbe16d37f97f68f08325dc1528" );
		compareSpeed( hash, "RIPEMD-160", log );
		log.writeln( "" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	void testSHA1()
	{
		IHash alg = new SHA1();
		// from 'Handbook of Applied Cryptography', page 345.
		checkMsgHash( alg, "", "da39a3ee5e6b4b0d3255bfef95601890afd80709" );
		checkMsgHash( alg, "a", "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8" );
		checkMsgHash( alg, "abc", "a9993e364706816aba3e25717850c26c9cd0d89d" );
		checkMsgHash( alg, "abcdefghijklmnopqrstuvwxyz", "32d10c7b8cf96570ca04ce37f2a19d84240d3a89" );
		crossCheckStd( alg, "SHA-1", log );
		checkStream( alg, "SHA-1", log );
		compareSpeed( alg, "SHA-1", log );
		log.writeln( "" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	void testSHA224()
	{
		IHash alg = new SHA224();
		// RFC 3874
		checkMsgHash( alg, "", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f" );
		checkMsgHash( alg, "a", "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5" );
		checkMsgHash( alg, "abc", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" );
		checkMsgHash( alg, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525" );
		checkMsgHash( alg, "The quick brown fox jumps over the lazy dog", "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525" );
		checkMsgHash( alg, "The quick brown fox jumps over the lazy dog.", "619cba8e8e05826e9b8c519c0a5c68f4fb653e8a3d8aa04bb2c8cd4c" );
		check1millionA( alg, "20794655980C91D8BBB4C1EA97618A4BF03F42581948B2EE4EE7AD67" );
		crossCheckStd( alg, "SHA-224", log );
		checkStream( alg, "SHA-224", log );
		compareSpeed( alg, "SHA-224", log );
		log.writeln( "" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	void testSHA256()
	{
		IHash alg = new SHA256();
		// from FIPS Draft 180-2
		checkMsgHash( alg, "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" );
		checkMsgHash( alg, "a", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb" );
		checkMsgHash( alg, "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" );
		checkMsgHash( alg, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" );
		checkMsgHash( alg, "The quick brown fox jumps over the lazy dog", "D7A8FBB3 07D78094 69CA9ABC B0082E4F 8D5651E4 6D3CDB76 2D02D0BF 37C9E592" );
		check1millionA( alg, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0" );

		crossCheckStd( alg, "SHA-256", log );
		checkStream( alg, "SHA-256", log );
		compareSpeed( alg, "SHA-256", log );
		log.writeln( "" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	void testSHA384()
	{
		IHash alg = new SHA384();

		checkMsgHash( alg, "", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b" );
		checkMsgHash( alg, "a", "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31" );
		checkMsgHash( alg, "abc", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7" );
		checkMsgHash( alg, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039" );
		checkMsgHash( alg, "The quick brown fox jumps over the lazy dog", "CA737F10 14A48F4C 0B6DD43C B177B0AF D9E51693 67544C49 4011E331 7DBF9A50 9CB1E5DC 1E85A941 BBEE3D7F 2AFBC9B1" );
		check1millionA( alg, "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985" );
		crossCheckStd( alg, "SHA-384", log );
		checkStream( alg, "SHA-384", log );
		log.writeln( "" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	void testSHA512()
	{
		IHash hash = new SHA512();

		checkMsgHash( hash, "", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" );
		checkMsgHash( hash, "a", "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75" );
		checkMsgHash( hash, "abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" );
		checkMsgHash( hash, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909" );
		checkMsgHash( hash, "The quick brown fox jumps over the lazy dog", "07E547D9 586F6A73 F73FBAC0 435ED769 51218FB7 D0C8D788 A309D785 436BBB64 2E93A252 A954F239 12547D1E 8A3B5ED6 E1BFD709 7821233F A0538F3D B854FEE6" );
		check1millionA( hash, "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b" );
		crossCheckStd( hash, "SHA-512", log );
		checkStream( hash, "SHA-512", log );
		compareSpeed( hash, "SHA-512", log );
		log.writeln( "" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	void testSHA512t224()
	{
		IHash hash = new SHA512t( 224 );
		checkMsgHash( hash, "", "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4" );
		checkMsgHash( hash, "a", "d5cdb9ccc769a5121d4175f2bfdd13d6310e0d3d361ea75d82108327" );
		checkMsgHash( hash, "abc", "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa" );
		checkMsgHash( hash, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9" );
		checkMsgHash( hash, "The quick brown fox jumps over the lazy dog", "944cd284 7fb54558 d4775db0 485a5000 3111c8e5 daa63fe7 22c6aa37" );
		check1millionA( hash, "37ab331d76f0d36de422bd0edeb22a28accd487b7a8453ae965dd287" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	void testSHA512t256()
	{
		IHash hash = new SHA512t( 256 );
		checkMsgHash( hash, "", "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a" );
		checkMsgHash( hash, "a", "455e518824bc0601f9fb858ff5c37d417d67c2f8e0df2babe4808858aea830f8" );
		checkMsgHash( hash, "abc", "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23" );
		checkMsgHash( hash, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a" );
		checkMsgHash( hash, "The quick brown fox jumps over the lazy dog", "dd9d67b3 71519c33 9ed8dbd2 5af90e97 6a1eeefd 4ad3d889 005e532f c5bef04d" );
		check1millionA( hash, "9a59a052930187a97038cae692f30708aa6491923ef5194394dc68d56c74fb21" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	void testKeccak()
	{
		Binary data1 = Bin( "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67" );
		Binary data2 = Bin(data1).add( "2e" );
		Binary data3 = new Binary( 0x10000, 'a' );
		Binary data4 = Bin().reserve( 0x10000 );
		for( int i = 0; i < 0x10000; ++i )
			data4.add( 'a' + (i % 26) );

		Keccak alg = new Keccak( 224 );
		checkMsgHash( alg, "", "f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd" );
		checkHash( alg, data1, "310aee6b30c47350576ac2873fa89fd190cdc488442f3ef654cf23fe" );
		checkHash( alg, data2, "c59d4eaeac728671c635ff645014e2afa935bebffdb5fbd207ffdeab" );
		checkHash( alg, data3, "f621e11c142fbf35fa8c22841c3a812ba1e0151be4f38d80b9f1ff53" );
		checkHash( alg, data4, "68b5fc8c87193155bba68a2485377e809ee4f81a85ef023b9e64add0" );

		alg = new Keccak( 256 );
		checkMsgHash( alg, "", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" );
		checkHash( alg, data1, "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15" );
		checkHash( alg, data2, "578951e24efd62a3d63a86f7cd19aaa53c898fe287d2552133220370240b572d" );
		checkHash( alg, data3, "0047a916daa1f92130d870b542e22d3108444f5a7e4429f05762fb647e6ed9ed" );
		checkHash( alg, data4, "db368762253ede6d4f1db87e0b799b96e554eae005747a2ea687456ca8bcbd03" );
		compareSpeed( alg, "Keccak-256", log );

		alg = new Keccak( 288 );
		checkMsgHash( alg, "", "6753e3380c09e385d0339eb6b050a68f66cfd60a73476e6fd6adeb72f5edd7c6f04a5d01" );
		checkHash( alg, data1, "0bbe6afae0d7e89054085c1cc47b1689772c89a41796891e197d1ca1b76f288154933ded" );
		checkHash( alg, data2, "82558a209b960ddeb531e6dcb281885b2400ca160472462486e79f071e88a3330a8a303d" );
		checkHash( alg, data3, "94049e1ad7ef5d5b0df2b880489e7ab09ec937c3bfc1b04470e503e1ac7b1133c18f86da" );
		checkHash( alg, data4, "a9cb5a75b5b81b7528301e72553ed6770214fa963956e790528afe420de33c074e6f4220" );

		alg = new Keccak( 384 );
		checkMsgHash( alg, "", "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff" );
		checkHash( alg, data1, "283990fa9d5fb731d786c5bbee94ea4db4910f18c62c03d173fc0a5e494422e8a0b3da7574dae7fa0baf005e504063b3" );
		checkHash( alg, data2, "9ad8e17325408eddb6edee6147f13856ad819bb7532668b605a24a2d958f88bd5c169e56dc4b2f89ffd325f6006d820b" );
		checkHash( alg, data3, "c704cfe7a1a53208ca9526cd24251e0acdc252ecd978eee05acd16425cfb404ea81f5a9e2e5e97784d63ee6a0618a398" );
		checkHash( alg, data4, "d4fe8586fd8f858dd2e4dee0bafc19b4c12b4e2a856054abc4b14927354931675cdcaf942267f204ea706c19f7beefc4" );

		alg = new Keccak( 512 );
		checkMsgHash( alg, "", "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e" );
		checkHash( alg, data1, "d135bb84d0439dbac432247ee573a23ea7d3c9deb2a968eb31d47c4fb45f1ef4422d6c531b5b9bd6f449ebcc449ea94d0a8f05f62130fda612da53c79659f609" );
		checkHash( alg, data2, "ab7192d2b11f51c7dd744e7b3441febf397ca07bf812cceae122ca4ded6387889064f8db9230f173f6d1ab6e24b6e50f065b039f799f5592360a6558eb52d760" );
		checkHash( alg, data3, "34341ead153aa1d1fdcf6cf624c2b4f6894b6fd16dc38bd4ec971ac0385ad54fafcb2e0ed86a1e509456f4246fdcb02c3172824cd649d9ad54c51f7fb49ea67c" );
		checkHash( alg, data4, "dc44d4f4d36b07ab5fc04016cbe53548e5a7778671c58a43cb379fd00c06719b8073141fc22191ffc3db5f8b8983ae8341fa37f18c1c969664393aa5ceade64e" );
		compareSpeed( alg, "Keccak-512", log );

		log.writeln( "" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	void testSHA3()
	{
		Binary data = Bin( 200, 0xA3 );
		
		SHA3 alg = new SHA3( 224 );
		checkHash( alg, "", "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7" );
		checkHash( alg, data, "9376816aba503f72f96ce7eb65ac095deee3be4bf9bbc2a1cb7e11e0" );
		checkMsgHash( alg, "The quick brown fox jumps over the lazy dog", "d15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795" );
		checkMsgHash( alg, "The quick brown fox jumps over the lazy dog.", "2d0708903833afabdd232a20201176e8b58c5be8a6fe74265ac54db0" );

		alg = new SHA3( 256 );
		checkHash( alg, "", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a" );
		checkHash( alg, data, "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787" );
		checkMsgHash( alg, "The quick brown fox jumps over the lazy dog", "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04" );
		checkMsgHash( alg, "The quick brown fox jumps over the lazy dog.", "a80f839cd4f83f6c3dafc87feae470045e4eb0d366397d5c6ce34ba1739f734d" );

		alg = new SHA3( 384 );
		checkHash( alg, "", "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004" );
		checkHash( alg, data, "1881de2ca7e41ef95dc4732b8f5f002b189cc1e42b74168ed1732649ce1dbcdd76197a31fd55ee989f2d7050dd473e8f" );
		checkMsgHash( alg, "The quick brown fox jumps over the lazy dog", "7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a9ebdf8be41" );
		checkMsgHash( alg, "The quick brown fox jumps over the lazy dog.", "1a34d81695b622df178bc74df7124fe12fac0f64ba5250b78b99c1273d4b080168e10652894ecad5f1f4d5b965437fb9" );

		alg = new SHA3( 512 );
		checkHash( alg, "", "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26" );
		checkHash( alg, data, "e76dfad22084a8b1467fcf2ffa58361bec7628edf5f3fdc0e4805dc48caeeca81b7c13c30adf52a3659584739a2df46be589c51ca1a4a8416df6545a1ce8ba00" );
		checkMsgHash( alg, "The quick brown fox jumps over the lazy dog", "01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450" );
		checkMsgHash( alg, "The quick brown fox jumps over the lazy dog.", "18f4f4bd419603f95538837003d9d254c26c23765565162247483f65c50303597bc9ce4d289f21d1c2f1f458828e33dc442100331b35e7eb031b5d38ba6460f8" );
	}

	// -----------------------------------------------------------------------------------------------------------------
	void testSHAKE()
	{
		Binary data = Bin( 200, 0xA3 );

		SHAKE alg = new SHAKE( 128 );
		MUST( alg.getHash(32).equals( "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26" ) );
		MUST( alg.getHash(512).equals( "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdefaee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32def58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c922a96188d032675c8ac850933c7aff1533b94c834adbb69c6115bad4692d8619f90b0cdf8a7b9c264029ac185b70b83f2801f2f4b3f70c593ea3aeeb613a7f1b1de33fd75081f592305f2e4526edc09631b10958f464d889f31ba010250fda7f1368ec2967fc84ef2ae9aff268e0b1700affc6820b523a3d917135f2dff2ee06bfe72b3124721d4a26c04e53a75e30e73a7a9c4a95d91c55d495e9f51dd0b5e9d83c6d5e8ce803aa62b8d654db53d09b8dcff273cdfeb573fad8bcd45578bec2e770d01efde86e721a3f7c6cce275dabe6e2143f1af18da7efddc4c7b70b5e345db93cc936bea323491ccb38a388f546a9ff00dd4e1300b9b2153d2041d205b443e41b45a653f2a5c4492c1add544512dda2529833462b71a41a45be97290b6f" ) );
		alg.process( data );
		MUST( alg.getHash(512).equals( "131ab8d2b594946b9c81333f9bb6e0ce75c3b93104fa3469d3917457385da037cf232ef7164a6d1eb448c8908186ad852d3f85a5cf28da1ab6fe3438171978467f1c05d58c7ef38c284c41f6c2221a76f12ab1c04082660250802294fb87180213fdef5b0ecb7df50ca1f8555be14d32e10f6edcde892c09424b29f597afc270c904556bfcb47a7d40778d390923642b3cbd0579e60908d5a000c1d08b98ef933f806445bf87f8b009ba9e94f7266122ed7ac24e5e266c42a82fa1bbefb7b8db0066e16a85e0493f07df4809aec084a593748ac3dde5a6d7aae1e8b6e5352b2d71efbb47d4caeed5e6d633805d2d323e6fd81b4684b93a2677d45e7421c2c6aea259b855a698fd7d13477a1fe53e5a4a6197dbec5ce95f505b520bcd9570c4a8265a7e01f89c0c002c59bfec6cd4a5c109258953ee5ee70cd577ee217af21fa70178f0946c9bf6ca8751793479f6b537737e40b6ed28511d8a2d7e73eb75f8daac912ff906e0ab955b083bac45a8e5e9b744c8506f37e9b4e749a184b30f43eb188d855f1b70d71ff3e50c537ac1b0f8974f0fe1a6ad295ba42f6aec74d123a7abedde6e2c0711cab36be5acb1a5a11a4b1db08ba6982efccd716929a7741cfc63aa4435e0b69a9063e880795c3dc5ef3272e11c497a91acf699fefee206227a44c9fb359fd56ac0a9a75a743cff6862f17d7259ab075216c0699511643b6439" ) );
		alg.process( Bin("The quick brown fox jumps over the lazy dog".getBytes()) );
		MUST( alg.getHash(32).equals( "f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66e" ) );
		alg.process( Bin("The quick brown fox jumps over the lazy dof".getBytes()) );
		MUST( alg.getHash(32).equals( "853f4538be0db9621a6cea659a06c1107b1f83f02b13d18297bd39d7411cf10c" ) );

		alg = new SHAKE( 256 );
		MUST( alg.getHash(64).equals( "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be" ) );
		MUST( alg.getHash(512).equals( "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86f3d122109e3b1fdd943b6aec468a2d621a7c06c6a957c62b54dafc3be87567d677231395f6147293b68ceab7a9e0c58d864e8efde4e1b9a46cbe854713672f5caaae314ed9083dab4b099f8e300f01b8650f1f4b1d8fcf3f3cb53fb8e9eb2ea203bdc970f50ae55428a91f7f53ac266b28419c3778a15fd248d339ede785fb7f5a1aaa96d313eacc890936c173cdcd0fab882c45755feb3aed96d477ff96390bf9a66d1368b208e21f7c10d04a3dbd4e360633e5db4b602601c14cea737db3dcf722632cc77851cbdde2aaf0a33a07b373445df490cc8fc1e4160ff118378f11f0477de055a81a9eda57a4a2cfb0c83929d310912f729ec6cfa36c6ac6a75837143045d791cc85eff5b21932f23861bcf23a52b5da67eaf7baae0f5fb1369db78f3ac45f8c4ac5671d85735cdddb09d2b1e34a1fc066ff4a162cb263d6541274ae2fcc865f618abe27c124cd8b074ccd516301b91875824d09958f341ef274bdab0bae316339894304e35877b0c28a9b1fd166c796b9cc258a064a8f57e27f2a" ) );
		alg.process( data );
		MUST( alg.getHash(512).equals( "cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a904d2d700caae7396ece96604440577da4f3aa22aeb8857f961c4cd8e06f0ae6610b1048a7f64e1074cd629e85ad7566048efc4fb500b486a3309a8f26724c0ed628001a1099422468de726f1061d99eb9e93604d5aa7467d4b1bd6484582a384317d7f47d750b8f5499512bb85a226c4243556e696f6bd072c5aa2d9b69730244b56853d16970ad817e213e470618178001c9fb56c54fefa5fee67d2da524bb3b0b61ef0e9114a92cdbb6cccb98615cfe76e3510dd88d1cc28ff99287512f24bfafa1a76877b6f37198e3a641c68a7c42d45fa7acc10dae5f3cefb7b735f12d4e589f7a456e78c0f5e4c4471fffa5e4fa0514ae974d8c2648513b5db494cea847156d277ad0e141c24c7839064cd08851bc2e7ca109fd4e251c35bb0a04fb05b364ff8c4d8b59bc303e25328c09a882e952518e1a8ae0ff265d61c465896973d7490499dc639fb8502b39456791b1b6ec5bcc5d9ac36a6df622a070d43fed781f5f149f7b62675e7d1a4d6dec48c1c7164586eae06a51208c0b791244d307726505c3ad4b26b6822377257aa152037560a739714a3ca79bd605547c9b78dd1f596f2d4f1791bc689a0e9b799a37339c04275733740143ef5d2b58b96a363d4e08076a1a9d7846436e4dca5728b6f760eef0ca92bf0be5615e96959d767197a0beeb" ) );
	}

	// -----------------------------------------------------------------------------------------------------------------
	void testGOST3411()
	{
		Binary data0 = Bin( 64 );
		Binary data1 = Bin( "012345678901234567890123456789012345678901234567890123456789012".getBytes() );
		Binary data2 = Bin( "d1e520e2e5f2f0e82c20d1f2f0e8e1eee6e820e2edf3f6e82c20e2e5fef2fa20f120eceef0ff20f1f2f0e5ebe0ece820ede020f5f0e0e1f0fbff20efebfaeafb20c8e3eef0e5e2fb" );

		IHash alg = new GOST3411_2012_256();
		checkHash( alg, "", "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb" );
		checkHash( alg, data0, "df1fda9ce83191390537358031db2ecaa6aa54cd0eda241dc107105e13636b95" );
		checkHash( alg, data1, "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500" );
		checkHash( alg, data2, "9dd2fe4e90409e5da87f53976d7405b0c0cac628fc669a741d50063c557e8f50" );

		alg = new GOST3411_2012_512();
		checkHash( alg, "", "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a" );
		checkHash( alg, data0, "b0fd29ac1b0df441769ff3fdb8dc564df67721d6ac06fb28ceffb7bbaa7948c6c014ac999235b58cb26fb60fb112a145d7b4ade9ae566bf2611402c552d20db7" );
		checkHash( alg, data1, "1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48" );
		checkHash( alg, data2, "1e88e62226bfca6f9994f1f2d51569e0daf8475a3b0fe61a5300eee46d961376035fe83549ada2b8620fcd7c496ce5b33f0cb9dddc2b6460143b03dabac9fb28" );
		compareSpeed( alg, "GOST 34.11-2012", log );

		alg = new GOST3411_94();
		checkMsgHash( alg, "", "981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0");
		checkMsgHash( alg, "This is message, length=32 bytes", "2cefc2f7b7bdc514e18ea57fa74ff357e7fa17d652c75f69cb1be7893ede48eb" );
		checkMsgHash( alg, "Suppose the original message has length = 50 bytes", "c3730c5cbccacf915ac292676f21e8bd4ef75331d9405e5f1a61dc3130a65011" );
		checkMsgHash( alg, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "73b70a39497de53a6e08c67b6d4db853540f03e9389299d9b0156ef7e85d0f61" );
		check1millionA( alg, "8693287aa62f9478f7cb312ec0866b6c4e4a0f11160441e8f4ffcd2715dd554f" );
		//compareSpeed( alg, "GOST 34.11-94", log );
	}

	// -----------------------------------------------------------------------------------------------------------------
	public static void main( String[] args )
	{
		new TestHashes();
	}

}
