/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ikev1;

import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPMessage;
import java.io.ByteArrayOutputStream;
import org.junit.Test;
import static org.junit.Assert.*;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ExchangeTypeEnum;
import static de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPMessageTest.getTestIKEv1MainModeSecurityAssociationMessage;
import de.rub.nds.ipsec.statemachineextractor.isakmp.NotificationPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.NotifyMessageTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.PayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv1MessageBuilderTest {
    
    /**
     * Test of fromByteArray method, of class IKEv1MessageBuilder.
     */
    @Test
    public void testFromByteArray_IKEv1MainModeSecurityAssociationMessage() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        getTestIKEv1MainModeSecurityAssociationMessage().writeBytes(baos);
        ISAKMPMessage instance = IKEv1MessageBuilder.fromByteArray(baos.toByteArray());
        assertEquals(1, instance.getPayloads().size());
    }
    
    /**
     * Test of fromByteArray method, of class IKEv1MessageBuilder.
     */
    @Test
    public void testFromByteArray_IKEv1PayloadMalformedNotification() throws Exception {
        byte[] wiresharkDump = DatatypeHelper.hexDumpToByteArray("00574fee41e8f80a3287d995d890aaed0b100500d9ac8bc0000000280000000c0000000101000010");
        ISAKMPMessage instance = IKEv1MessageBuilder.fromByteArray(wiresharkDump);
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("3287d995d890aaed"), instance.getResponderCookie());
        assertEquals(ExchangeTypeEnum.Informational, instance.getExchangeType());
        assertEquals(1, instance.getPayloads().size());
        assertEquals(PayloadTypeEnum.Notification, instance.getPayloads().get(0).getType());
        assertEquals(NotifyMessageTypeEnum.PayloadMalformed, ((NotificationPayload)instance.getPayloads().get(0)).getNotifyMessageType());
    }

}
