/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.util;

import com.sun.org.apache.xpath.internal.operations.And;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEDHGroupEnum;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class CryptoHelperTest {

    static {
        CryptoHelper.prepare();
    }

    /**
     * Test of createModPPublicKeyFromBytes method, of class CryptoHelper.
     */
    @Test
    public void testCreateModPPublicKeyFromBytes() throws Exception {
        boolean shortCase = false, longCase = false;
        DHParameterSpec algoSpec = (DHParameterSpec) IKEDHGroupEnum.GROUP1_768.getAlgorithmParameterSpec();
        while (!shortCase || !longCase) {
            KeyPair keypair = CryptoHelper.generateKeyPair("DiffieHellman", algoSpec);
            byte[] publicKeyBytes = CryptoHelper.publicKey2Bytes(keypair.getPublic());
            if ((publicKeyBytes[0] & 0x80) != 0) {
                shortCase = true;
            } else {
                longCase = true;
            }
            DHPublicKey result = CryptoHelper.createModPPublicKeyFromBytes(algoSpec, publicKeyBytes);
            assertEquals(((DHPublicKey) keypair.getPublic()).getY(), result.getY());
        }
    }

    /**
     * Test of createECPublicKeyFromBytes method, of class CryptoHelper.
     */
    @Test
    public void testCreateECPublicKeyFromBytes() throws Exception {
        boolean xShortCase = false, xLongCase = false;
        boolean yShortCase = false, yLongCase = false;
        ECParameterSpec algoSpec = (ECParameterSpec) IKEDHGroupEnum.GROUP19_256.getAlgorithmParameterSpec();
        while (!xShortCase || !xLongCase || !yShortCase || !yLongCase) {
            KeyPair keypair = CryptoHelper.generateKeyPair("EC", algoSpec);
            byte[] publicKeyBytes = CryptoHelper.publicKey2Bytes(keypair.getPublic());
            if ((publicKeyBytes[0] & 0x80) != 0) {
                xShortCase = true;
            } else {
                xLongCase = true;
            }
            if ((publicKeyBytes[32] & 0x80) != 0) {
                yShortCase = true;
            } else {
                yLongCase = true;
            }
            ECPublicKey result = CryptoHelper.createECPublicKeyFromBytes(algoSpec, publicKeyBytes);
            assertEquals(((ECPublicKey) keypair.getPublic()).getW(), result.getW());
        }
    }

    /**
     * Test of createECPublicKeyFromBytes method, of class CryptoHelper.
     */
    @Test
    public void testEcPublicKey2BytesWithShortValues() throws Exception {
        ECParameterSpec algoSpec = (ECParameterSpec) IKEDHGroupEnum.GROUP19_256.getAlgorithmParameterSpec();
        BigInteger x = new BigInteger("754f8d9282cac51410fc7bbe801dcfb1251db62498fa5e6a407cd51f43a951", 16);
        BigInteger y = new BigInteger("aeddbbe5d4a0242dea4f6a8229d9f99362c85d4e3f8c61fefe33c685b1233ee6", 16);
        ECPoint ecPoint = new ECPoint(x, y);
        ECPublicKeySpec keySpec = new ECPublicKeySpec(ecPoint, algoSpec);
        KeyFactory kf = KeyFactory.getInstance("EC");
        PublicKey publicKey = kf.generatePublic(keySpec);
        CryptoHelper.publicKey2Bytes(publicKey);
    }
}
