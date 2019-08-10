/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import de.rub.nds.ipsec.statemachineextractor.util.CryptoHelper;
import static de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper.hexDumpToByteArray;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IdentificationPayloadPKETest {

    public static KeyPair TESTKEYPAIR;
    public static final int TESTKEYPAIR_BITLEN = 1024;

    static {
        CryptoHelper.prepare();
    }
    
    static {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(TESTKEYPAIR_BITLEN);
            TESTKEYPAIR = keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
    }

    public static PKCS1EncryptedISAKMPPayload getTestIdentificationPayloadPKE() {
        IdentificationPayload idPayload = new IdentificationPayload();
        idPayload.setIdType(IDTypeEnum.ID_IPV4_ADDR);
        idPayload.setIdentificationData(new byte[]{10, 0, 0, 0});
        PKCS1EncryptedISAKMPPayload instance = new PKCS1EncryptedISAKMPPayload(idPayload, TESTKEYPAIR.getPrivate(), TESTKEYPAIR.getPublic());
        try {
            instance.encrypt();
        } catch (GeneralSecurityException ex) {
            throw new RuntimeException(ex);
        }
        return instance;
    }
    
    private static final String TESTDATA = "50e6b66c8dc322e863066bcd77fa1986a6"
            + "7c3de6b131d69105fb8b71127c7ba96edf64b5f5727e650353b3f3ec573247a"
            + "7b437db068376d9f6d53d854b38cfce5067877857f597de268cb55722ce271b"
            + "b3f92e4c7e8e153970a53369d570043294d83c4a3517dd09150b54e51e09a47"
            + "9e66d74651c1c970f8c48e5a1a58c10881136a77cb354037c3f19dac9b50458"
            + "2299e6b8314bb46d58f70d0b516e7f8219d8f87388767e3e7f1c8e58bd9ed48"
            + "92c54acb20e9b9e6d02d1f969274b19d64068ee3f6e503276ed6f6652ee6cf4"
            + "ec782b4b1dad3ce13a04e6664e038f842ce86d3337de94ca195ec95fc6731e4"
            + "8bbc02258cc6199214efd147701302d9bb61d";
    
    public static PKCS1EncryptedISAKMPPayload getTestStaticIdentificationPayloadPKE() {
        PKCS1EncryptedISAKMPPayload instance = new PKCS1EncryptedISAKMPPayload(new IdentificationPayload(), TESTKEYPAIR.getPrivate(), TESTKEYPAIR.getPublic());
        instance.encryptedBody = hexDumpToByteArray(TESTDATA);
        instance.isInSync = true;
        return instance;
    }

    /**
     * Test of writeBytes method, of class IdentificationPayloadPKE.
     */
    @Test
    public void testWriteBytes() {
        PKCS1EncryptedISAKMPPayload instance = getTestIdentificationPayloadPKE();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        instance.writeBytes(baos);
        byte[] result = baos.toByteArray();
        assertEquals((TESTKEYPAIR_BITLEN / 8) + 4, result[3] & 0xFF);
        assertEquals((TESTKEYPAIR_BITLEN / 8) + 4, result.length);
    }

    /**
     * Test of fromStream method, of class IdentificationPayloadPKE.
     */
    @Test
    public void testFromStream() throws Exception {
        PKCS1EncryptedISAKMPPayload origInstance = getTestIdentificationPayloadPKE();
        IdentificationPayload plainOrigInstance = (IdentificationPayload) origInstance.getPlainPayload();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        origInstance.writeBytes(baos);
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        PKCS1EncryptedISAKMPPayload newInstance = PKCS1EncryptedISAKMPPayload.fromStream(IdentificationPayload.class, bais, TESTKEYPAIR.getPrivate(), TESTKEYPAIR.getPublic());
        IdentificationPayload newPlainPayload = (IdentificationPayload) newInstance.getPlainPayload();
        assertArrayEquals(plainOrigInstance.getIdentificationData(), newPlainPayload.getIdentificationData());
        assertEquals(0, bais.available());
    }

}
