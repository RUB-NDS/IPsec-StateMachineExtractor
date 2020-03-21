/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ipsec.attributes;

import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IPsecAttributeFactoryTest {

    /**
     * Test lazy loading.
     */
    @Test
    public void testFromStreamBasic() throws Exception {
        byte[] bytes = DatatypeHelper.intTo4ByteArray(0x80010001);
        IPsecAttribute result = IPsecAttributeFactory.fromStream(new ByteArrayInputStream(bytes));
        assertEquals("SECONDS", result.toString());
    }
    
    @Test
    public void testFromStreamVariableLength() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(DatatypeHelper.intTo4ByteArray(0x00020004), 0, 4);
        baos.write(DatatypeHelper.intTo4ByteArray(0x00000E10), 0, 4);
        byte[] bytes = baos.toByteArray();
        IPsecAttribute result = IPsecAttributeFactory.fromStream(new ByteArrayInputStream(bytes));
        assertEquals("0002000400000E10", DatatypeHelper.byteArrayToHexDump(result.getBytes()));
    }

}
