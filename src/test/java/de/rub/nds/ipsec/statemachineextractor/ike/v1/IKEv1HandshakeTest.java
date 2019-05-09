/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1;

import de.rub.nds.ipsec.statemachineextractor.isakmp.KeyExchangePayload;
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
        assertTrue(result.getLength() == 196 || result.getLength() == 197);
    }
    
}
