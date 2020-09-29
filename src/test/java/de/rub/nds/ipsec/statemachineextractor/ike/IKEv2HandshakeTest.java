/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike;

import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.EncryptedIKEv2Message;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.IKEv2Message;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.SecurityAssociationPayloadv2;
import de.rub.nds.ipsec.statemachineextractor.util.CryptoHelper;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.net.InetAddress;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Ignore;
import org.junit.Test;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv2HandshakeTest {

    static {
        CryptoHelper.prepare();
    }

    @Test
    @Ignore
    public void testHandhake() throws Exception {
        IKEHandshake handshake = new IKEHandshake(500, InetAddress.getByName("10.0.3.10"), 500);
        SecurityAssociationPayloadv2 sa;
        IKEMessage answer;
        
        IKEv2Message msg = new IKEv2Message();
        msg.setExchangeType(ExchangeTypeEnum.IKE_SA_INIT);
        msg.setInitiatorFlag(true);
        msg.setVersionFlag(false);
        msg.setResponseFlag(false);
        sa = SecurityAssociationPayloadFactory.V2_P1_AES_128_CBC_SHA1;
        msg.addPayload(sa);
        //handshake.adjustCiphersuite(sa);
        msg.addPayload(handshake.prepareIKEv2KeyExchangePayload(handshake.getNextv2MessageID()));
        msg.addPayload(handshake.prepareIKEv2NoncePayload(handshake.getNextv2MessageID()));
//        System.out.println(DatatypeHelper.byteArrayToHexDump(handshake.secrets_v2.getHandshakeSA().getDhKeyPair().getPrivate().getEncoded()));
//        System.out.println(DatatypeHelper.byteArrayToHexDump(handshake.secrets_v2.getHandshakeSA().getDhKeyPair().getPublic().getEncoded()));
        answer = handshake.exchangeMessage(msg);

        msg = new IKEv2Message();
        msg.setExchangeType(ExchangeTypeEnum.IKE_AUTH);
        msg.setInitiatorFlag(true);
        msg.setVersionFlag(false);
        msg.setResponseFlag(false);
        msg.addPayload(handshake.prepareIKEv2IdentificationInitiator());
        msg.addPayload(handshake.prepareIKEv2AuthenticationPayload());
        sa = SecurityAssociationPayloadFactory.V2_P2_AES_128_CBC_SHA1_ESN;
        msg.addPayload(sa);
        msg.addPayload(handshake.prepareIKEv2TrafficSelectorPayloadInitiator());
        msg.addPayload(handshake.prepareIKEv2TrafficSelectorPayloadResponder());
        answer = handshake.exchangeMessage(msg);
    }
}
