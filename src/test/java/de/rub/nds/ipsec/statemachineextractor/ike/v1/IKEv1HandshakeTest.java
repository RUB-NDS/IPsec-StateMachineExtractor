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
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPMessage;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPMessageTest;
import de.rub.nds.ipsec.statemachineextractor.isakmp.KeyExchangePayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.NoncePayload;
import java.net.InetAddress;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv1HandshakeTest {

    public IKEv1HandshakeTest() {
        if (!(Security.getProviders()[0] instanceof BouncyCastleProvider)) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    }

    /**
     * Test of prepareKeyExchangePayload method, of class IKEv1Handshake.
     */
    @Test
    public void testPrepareKeyExchangePayload() throws Exception {
        IKEv1Handshake instance = new IKEv1Handshake(0, InetAddress.getLocalHost(), 500);
        KeyExchangePayload result = instance.prepareKeyExchangePayload();
        assertTrue(result.getLength() <= instance.group.getPublicKeySizeInBytes() + 4);
    }
    
    /**
     * Test of prepareKeyExchangePayload method, of class IKEv1Handshake.
     */
    @Test
    public void testPrepareKeyExchangePayloadEC() throws Exception {
        IKEv1Handshake instance = new IKEv1Handshake(0, InetAddress.getLocalHost(), 500);
        instance.group = IKEDHGroupEnum.GROUP19_256;
        KeyExchangePayload result = instance.prepareKeyExchangePayload();
        assertEquals(instance.group.getPublicKeySizeInBytes() + 4, result.getLength());
    }

    /**
     * Test of prepareNoncePayload method, of class IKEv1Handshake.
     */
    @Test
    public void testPrepareNoncePayload() throws Exception {
        IKEv1Handshake instance = new IKEv1Handshake(0, InetAddress.getLocalHost(), 500);
        NoncePayload result = instance.prepareNoncePayload();
        assertEquals(instance.nonceLen + 4, result.getLength());
    }

    /**
     * Test of extractProperties method, of class IKEv1Handshake.
     */
    @Test
    public void testExtractProperties() throws Exception {
        ISAKMPMessage msg = ISAKMPMessageTest.getTestIKEv1MainModeSecurityAssociationMessage();
        IKEv1Handshake instance = new IKEv1Handshake(0, InetAddress.getLocalHost(), 500);
        instance.extractProperties(msg);
    }
}
