/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp;

import de.rub.nds.ipsec.statemachineextractor.ike.IKEPayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.CipherAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.util.CryptoHelper;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.io.ByteArrayInputStream;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class EncryptedISAKMPMessageTest {
    
    static {
        CryptoHelper.prepare();
    }

    /**
     * Test of decrypt method, of class EncryptedISAKMPMessage.
     */
    @Test
    public void testDecrypt() throws Exception {
        byte[] bytes = DatatypeHelper.hexDumpToByteArray("05041c1d00fd6eff2e9ac75cd77f5cc6081005015c9704a70000004c03ea6c1d88aa6ca97a94ff3f2c641c1542c69e66d5b8e9965fea0a19eae77985d22f9acb0164b32223c9b3b384b67516");
        byte[] key = DatatypeHelper.hexDumpToByteArray("C9FC2BDBD56171BE58C4ABD940E5D58E");
        byte[] iv = DatatypeHelper.hexDumpToByteArray("3D374A012E6BBC7AD042F15490F403B1");
        byte[] expected = DatatypeHelper.hexDumpToByteArray("0B0000186CCBBDD749962C1C0CDE5E55E9BD8B73F779BA530000000C0000000101000010");
        EncryptedISAKMPMessage encMessage = new EncryptedISAKMPMessage(new SecretKeySpec(key, "AES"), CipherAttributeEnum.AES_CBC, iv);
        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        bais.skip(ISAKMPMessage.IKE_MESSAGE_HEADER_LEN);
        encMessage.setCiphertext(bais, bais.available());
        encMessage.setNextPayload(IKEPayloadTypeEnum.Hash);
        encMessage.decrypt();
        assertArrayEquals(expected, encMessage.getPlaintext());
        assertEquals(2, encMessage.getPayloads().size());
        assertEquals(encMessage.getPayloads().get(0).getType(), IKEPayloadTypeEnum.Hash);
        assertEquals(encMessage.getPayloads().get(1).getType(), IKEPayloadTypeEnum.Notification);
        assertEquals(0, bais.available());
    }
    
}
