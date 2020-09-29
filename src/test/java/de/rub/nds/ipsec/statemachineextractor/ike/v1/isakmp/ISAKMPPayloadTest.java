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
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class ISAKMPPayloadTest {

    /**
     * Test of getBytes method, of class ISAKMPPayload.
     */
    @Test
    public void testGetBytes() {
        ISAKMPPayload instance = new ISAKMPPayloadMockImpl();
        byte[] expResult = new byte[]{
            0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x2c,
            0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x24,
            0x01, 0x01, 0x00, 0x00, -128, 0x01, 0x00, 0x07,
            -128, 0x0e, 0x00, -128, -128, 0x02, 0x00, 0x02,
            -128, 0x04, 0x00, 0x05, -128, 0x03, 0x00, 0x04,
            -128, 0x0b, 0x00, 0x01, -128, 0x0c, 0x70, -128
        };
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        instance.writeBytes(baos);
        byte[] result = baos.toByteArray();
        assertArrayEquals(expResult, result);
    }

    public class ISAKMPPayloadMockImpl extends ISAKMPPayload {

        public ISAKMPPayloadMockImpl() {
            super(IKEPayloadTypeEnum.SecurityAssociation);
        }

        @Override
        public int getLength() {
            return 56;
        }

        @Override
        public void writeBytes(ByteArrayOutputStream baos) {
            super.writeBytes(baos);
            baos.write(new byte[]{
                0x00, 0x00, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x2c,
                0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x24,
                0x01, 0x01, 0x00, 0x00, -128, 0x01, 0x00, 0x07,
                -128, 0x0e, 0x00, -128, -128, 0x02, 0x00, 0x02,
                -128, 0x04, 0x00, 0x05, -128, 0x03, 0x00, 0x04,
                -128, 0x0b, 0x00, 0x01, -128, 0x0c, 0x70, -128
            }, 0, getLength() - GENERIC_PAYLOAD_HEADER_LEN);
        }

        @Override
        protected void fillFromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        protected void setBody(byte[] body) throws ISAKMPParsingException {
            throw new UnsupportedOperationException("Not supported yet.");
        }
    }
}
