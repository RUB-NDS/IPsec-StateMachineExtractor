/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1;

import de.rub.nds.ipsec.statemachineextractor.ike.IKEDHGroupEnum;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import javax.crypto.KeyAgreement;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;

/**
 * Test values from RFC 5903.
 * 
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEDHGroupEnumTest {

    public IKEDHGroupEnumTest() {
        if (!(Security.getProviders()[0] instanceof BouncyCastleProvider)) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    }

    @Test
    public void testECDH() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
        keyPairGen.initialize((ECParameterSpec)IKEDHGroupEnum.GROUP19_256.getAlgorithmParameterSpec());
        KeyPair keyPairA = keyPairGen.generateKeyPair();
        KeyPair keyPairB = keyPairGen.generateKeyPair();
        KeyAgreement keyAgreementA = KeyAgreement.getInstance("ECDH");
        KeyAgreement keyAgreementB = KeyAgreement.getInstance("ECDH");
        keyAgreementA.init(keyPairA.getPrivate());
        keyAgreementB.init(keyPairB.getPrivate());
        keyAgreementA.doPhase(keyPairB.getPublic(), true);
        keyAgreementB.doPhase(keyPairA.getPublic(), true);
        byte[] secretA = keyAgreementA.generateSecret();
        byte[] secretB = keyAgreementB.generateSecret();
        assertArrayEquals(secretA, secretB);
    }

    /**
     * Test of getECParameterSpec method, of class IKEv1ECDHGroupEnum.
     */
    @Test
    public void testGetECParameterSpec_GROUP19_256() throws Exception {
        ECParameterSpec ecParameterSpec = (ECParameterSpec)IKEDHGroupEnum.GROUP19_256.getAlgorithmParameterSpec();        
        ECPrivateKeySpec priKeySpecA = new ECPrivateKeySpec(new BigInteger("C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433", 16), ecParameterSpec);
        ECPrivateKeySpec priKeySpecB = new ECPrivateKeySpec(new BigInteger("C6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53", 16), ecParameterSpec);
        ECPublicKeySpec pubKeySpecA = new ECPublicKeySpec(new ECPoint(new BigInteger("DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180", 16), new BigInteger("5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3", 16)), ecParameterSpec);
        ECPublicKeySpec pubKeySpecB = new ECPublicKeySpec(new ECPoint(new BigInteger("D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63", 16), new BigInteger("56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB", 16)), ecParameterSpec);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        ECPrivateKey priKeyA = (ECPrivateKey) keyFactory.generatePrivate(priKeySpecA);
        ECPrivateKey priKeyB = (ECPrivateKey) keyFactory.generatePrivate(priKeySpecB);
        ECPublicKey pubKeyA = (ECPublicKey) keyFactory.generatePublic(pubKeySpecA);
        ECPublicKey pubKeyB = (ECPublicKey) keyFactory.generatePublic(pubKeySpecB);
        KeyAgreement keyAgreementA = KeyAgreement.getInstance("ECDH");
        KeyAgreement keyAgreementB = KeyAgreement.getInstance("ECDH");
        keyAgreementA.init(priKeyA);
        keyAgreementB.init(priKeyB);
        keyAgreementA.doPhase(pubKeyB, true);
        keyAgreementB.doPhase(pubKeyA, true);
        byte[] secretA = keyAgreementA.generateSecret();
        byte[] secretB = keyAgreementB.generateSecret();
        byte[] expectedSecret = DatatypeHelper.hexDumpToByteArray("D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE");
        assertArrayEquals(expectedSecret, secretA);
        assertArrayEquals(expectedSecret, secretB);
    }
    
    /**
     * Test of getECParameterSpec method, of class IKEv1ECDHGroupEnum.
     */
    @Test
    public void testGetECParameterSpec_GROUP20_384() throws Exception {
        ECParameterSpec ecParameterSpec = (ECParameterSpec)IKEDHGroupEnum.GROUP20_384.getAlgorithmParameterSpec();        
        ECPrivateKeySpec priKeySpecA = new ECPrivateKeySpec(new BigInteger("099F3C7034D4A2C699884D73A375A67F7624EF7C6B3C0F160647B67414DCE655E35B538041E649EE3FAEF896783AB194", 16), ecParameterSpec);
        ECPrivateKeySpec priKeySpecB = new ECPrivateKeySpec(new BigInteger("41CB0779B4BDB85D47846725FBEC3C9430FAB46CC8DC5060855CC9BDA0AA2942E0308312916B8ED2960E4BD55A7448FC", 16), ecParameterSpec);
        ECPublicKeySpec pubKeySpecA = new ECPublicKeySpec(new ECPoint(new BigInteger("667842D7D180AC2CDE6F74F37551F55755C7645C20EF73E31634FE72B4C55EE6DE3AC808ACB4BDB4C88732AEE95F41AA", 16), new BigInteger("9482ED1FC0EEB9CAFC4984625CCFC23F65032149E0E144ADA024181535A0F38EEB9FCFF3C2C947DAE69B4C634573A81C", 16)), ecParameterSpec);
        ECPublicKeySpec pubKeySpecB = new ECPublicKeySpec(new ECPoint(new BigInteger("E558DBEF53EECDE3D3FCCFC1AEA08A89A987475D12FD950D83CFA41732BC509D0D1AC43A0336DEF96FDA41D0774A3571", 16), new BigInteger("DCFBEC7AACF3196472169E838430367F66EEBE3C6E70C416DD5F0C68759DD1FFF83FA40142209DFF5EAAD96DB9E6386C", 16)), ecParameterSpec);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        ECPrivateKey priKeyA = (ECPrivateKey) keyFactory.generatePrivate(priKeySpecA);
        ECPrivateKey priKeyB = (ECPrivateKey) keyFactory.generatePrivate(priKeySpecB);
        ECPublicKey pubKeyA = (ECPublicKey) keyFactory.generatePublic(pubKeySpecA);
        ECPublicKey pubKeyB = (ECPublicKey) keyFactory.generatePublic(pubKeySpecB);
        KeyAgreement keyAgreementA = KeyAgreement.getInstance("ECDH");
        KeyAgreement keyAgreementB = KeyAgreement.getInstance("ECDH");
        keyAgreementA.init(priKeyA);
        keyAgreementB.init(priKeyB);
        keyAgreementA.doPhase(pubKeyB, true);
        keyAgreementB.doPhase(pubKeyA, true);
        byte[] secretA = keyAgreementA.generateSecret();
        byte[] secretB = keyAgreementB.generateSecret();
        byte[] expectedSecret = DatatypeHelper.hexDumpToByteArray("11187331C279962D93D604243FD592CB9D0A926F422E47187521287E7156C5C4D603135569B9E9D09CF5D4A270F59746");
        assertArrayEquals(expectedSecret, secretA);
        assertArrayEquals(expectedSecret, secretB);
    }
    
    /**
     * Test of getECParameterSpec method, of class IKEv1ECDHGroupEnum.
     */
    @Test
    public void testGetECParameterSpec_GROUP21_521() throws Exception {
        ECParameterSpec ecParameterSpec = (ECParameterSpec)IKEDHGroupEnum.GROUP21_521.getAlgorithmParameterSpec();        
        ECPrivateKeySpec priKeySpecA = new ECPrivateKeySpec(new BigInteger("0037ADE9319A89F4DABDB3EF411AACCCA5123C61ACAB57B5393DCE47608172A095AA85A30FE1C2952C6771D937BA9777F5957B2639BAB072462F68C27A57382D4A52", 16), ecParameterSpec);
        ECPrivateKeySpec priKeySpecB = new ECPrivateKeySpec(new BigInteger("0145BA99A847AF43793FDD0E872E7CDFA16BE30FDC780F97BCCC3F078380201E9C677D600B343757A3BDBF2A3163E4C2F869CCA7458AA4A4EFFC311F5CB151685EB9", 16), ecParameterSpec);
        ECPublicKeySpec pubKeySpecA = new ECPublicKeySpec(new ECPoint(new BigInteger("0015417E84DBF28C0AD3C278713349DC7DF153C897A1891BD98BAB4357C9ECBEE1E3BF42E00B8E380AEAE57C2D107564941885942AF5A7F4601723C4195D176CED3E", 16), new BigInteger("017CAE20B6641D2EEB695786D8C946146239D099E18E1D5A514C739D7CB4A10AD8A788015AC405D7799DC75E7B7D5B6CF2261A6A7F1507438BF01BEB6CA3926F9582", 16)), ecParameterSpec);
        ECPublicKeySpec pubKeySpecB = new ECPublicKeySpec(new ECPoint(new BigInteger("00D0B3975AC4B799F5BEA16D5E13E9AF971D5E9B984C9F39728B5E5739735A219B97C356436ADC6E95BB0352F6BE64A6C2912D4EF2D0433CED2B6171640012D9460F", 16), new BigInteger("015C68226383956E3BD066E797B623C27CE0EAC2F551A10C2C724D9852077B87220B6536C5C408A1D2AEBB8E86D678AE49CB57091F4732296579AB44FCD17F0FC56A", 16)), ecParameterSpec);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        ECPrivateKey priKeyA = (ECPrivateKey) keyFactory.generatePrivate(priKeySpecA);
        ECPrivateKey priKeyB = (ECPrivateKey) keyFactory.generatePrivate(priKeySpecB);
        ECPublicKey pubKeyA = (ECPublicKey) keyFactory.generatePublic(pubKeySpecA);
        ECPublicKey pubKeyB = (ECPublicKey) keyFactory.generatePublic(pubKeySpecB);
        KeyAgreement keyAgreementA = KeyAgreement.getInstance("ECDH");
        KeyAgreement keyAgreementB = KeyAgreement.getInstance("ECDH");
        keyAgreementA.init(priKeyA);
        keyAgreementB.init(priKeyB);
        keyAgreementA.doPhase(pubKeyB, true);
        keyAgreementB.doPhase(pubKeyA, true);
        byte[] secretA = keyAgreementA.generateSecret();
        byte[] secretB = keyAgreementB.generateSecret();
        byte[] expectedSecret = DatatypeHelper.hexDumpToByteArray("01144C7D79AE6956BC8EDB8E7C787C4521CB086FA64407F97894E5E6B2D79B04D1427E73CA4BAA240A34786859810C06B3C715A3A8CC3151F2BEE417996D19F3DDEA");
        assertArrayEquals(expectedSecret, secretA);
        assertArrayEquals(expectedSecret, secretB);
    }

}