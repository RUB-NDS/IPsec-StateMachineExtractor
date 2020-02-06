/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.IKEv1Ciphersuite;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.CipherAttributeEnum;
import static de.rub.nds.ipsec.statemachineextractor.isakmp.SymmetricallyEncryptedISAKMPPayloadTest.TEST_HASH;
import static de.rub.nds.ipsec.statemachineextractor.isakmp.SymmetricallyEncryptedISAKMPPayloadTest.TEST_HASH_ENC;
import static de.rub.nds.ipsec.statemachineextractor.isakmp.SymmetricallyEncryptedISAKMPPayloadTest.TEST_IV;
import static de.rub.nds.ipsec.statemachineextractor.isakmp.SymmetricallyEncryptedISAKMPPayloadTest.TEST_KEY_DES;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class SymmetricallyEncryptedIdentificationPayloadHuaweiStyleTest {
    
    private static final byte[] TEST_ID_PAYLOAD_ENC = DatatypeHelper.hexDumpToByteArray("000000180B0000000AE7097DDF4EABE455028CFAF36400CD");
    
    /**
     * Test of encrypt method, of class SymmetricallyEncryptedIdentificationPayloadHuaweiStyle.
     */
    @Test
    public void testEncrypt() throws Exception {
        IdentificationPayload idPayload = new IdentificationPayload();
        idPayload.setIdType(IDTypeEnum.KEY_ID);
        idPayload.setIdentificationData(TEST_HASH);
        IKEv1Ciphersuite cs = new IKEv1Ciphersuite();
        cs.setCipher(CipherAttributeEnum.DES_CBC);
        SymmetricallyEncryptedIdentificationPayloadHuaweiStyle instance = new SymmetricallyEncryptedIdentificationPayloadHuaweiStyle(idPayload, cs, TEST_KEY_DES, TEST_IV);
        assertArrayEquals(TEST_HASH_ENC, instance.getCiphertext());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        instance.writeBytes(baos);
        assertArrayEquals(TEST_ID_PAYLOAD_ENC, baos.toByteArray());
    }

    /**
     * Test of fromStream method, of class SymmetricallyEncryptedIdentificationPayloadHuaweiStyle.
     */
    @Test
    public void testFromStream() throws Exception {
        IKEv1Ciphersuite cs = new IKEv1Ciphersuite();
        cs.setCipher(CipherAttributeEnum.DES_CBC);
        ByteArrayInputStream bais = new ByteArrayInputStream(TEST_ID_PAYLOAD_ENC);
        SymmetricallyEncryptedIdentificationPayloadHuaweiStyle instance = SymmetricallyEncryptedIdentificationPayloadHuaweiStyle.fromStream(bais, cs, TEST_KEY_DES, TEST_IV);
        assertArrayEquals(TEST_HASH, ((IdentificationPayload) instance.getUnderlyingPayload()).getIdentificationData());
        assertEquals(0, bais.available());
    }

}
