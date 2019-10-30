/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.AuthAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.CipherAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.DHGroupAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.LifeDurationAttribute;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.HashAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.KeyLengthAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.LifeTypeAttributeEnum;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class TransformPayloadTest {

    public static TransformPayload getTestTransformPayload() {
        TransformPayload instance = new TransformPayload();
        instance.setTransformNumber((byte)0);
        instance.addAttribute(CipherAttributeEnum.AES_CBC);
        instance.addAttribute(KeyLengthAttributeEnum.L128);
        instance.addAttribute(HashAttributeEnum.SHA1);
        instance.addAttribute(DHGroupAttributeEnum.GROUP5);
        instance.addAttribute(AuthAttributeEnum.PKE);
        instance.addAttribute(LifeTypeAttributeEnum.SECONDS);
        instance.addAttribute(LifeDurationAttribute.get(28800));
        return instance;
    }
    
    /**
     * Test of writeBytes method, of class TransformPayload.
     */
    @Test
    public void testWriteBytes() {
        TransformPayload instance = getTestTransformPayload();
        byte[] expResult = new byte[]{
            0x00, 0x00, 0x00, 0x24, 0x00, 0x01, 0x00, 0x00,
            -128, 0x01, 0x00, 0x07, -128, 0x0e, 0x00, -128,
            -128, 0x02, 0x00, 0x02, -128, 0x04, 0x00, 0x05,
            -128, 0x03, 0x00, 0x04, -128, 0x0b, 0x00, 0x01,
            -128, 0x0c, 0x70, -128
        };
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        instance.writeBytes(baos);
        byte[] result = baos.toByteArray();
        assertArrayEquals(expResult, result);
    }
    
    /**
     * Test of fromStream method, of class TransformPayload.
     */
    @Test
    public void testFromStream() throws ISAKMPParsingException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        getTestTransformPayload().writeBytes(baos);
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        TransformPayload instance = TransformPayload.fromStream(bais, ProtocolIDEnum.ISAKMP);
        assertEquals(0, bais.available());
        assertEquals(1, instance.getTransformId().getValue());
        assertEquals(0, instance.getTransformNumber());
    }
}
