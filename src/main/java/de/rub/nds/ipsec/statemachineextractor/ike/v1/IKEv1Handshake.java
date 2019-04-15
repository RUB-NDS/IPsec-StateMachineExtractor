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
import de.rub.nds.ipsec.statemachineextractor.isakmp.IDTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPMessage;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPParsingException;
import de.rub.nds.ipsec.statemachineextractor.isakmp.IdentificationPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.KeyExchangePayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.TransformPayload;
import static de.rub.nds.ipsec.statemachineextractor.learning.IKEMessageMapper.getPSKSecurityAssociationPayload;
import de.rub.nds.ipsec.statemachineextractor.util.LoquaciousClientUdpTransportHandler;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECParameterSpec;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv1Handshake {

    LoquaciousClientUdpTransportHandler udpTH;
    private byte[] initiatorCookie, responderCookie;
    private KeyPair keyPair;

    // The default "ciphersuite"
    private IKEDHGroupEnum group = IKEDHGroupEnum.GROUP5_1536;

    public IKEv1Handshake(long timeout, InetAddress remoteAddress, int port) {
        this.udpTH = new LoquaciousClientUdpTransportHandler(timeout, remoteAddress.getHostAddress(), port);
    }

    public ISAKMPMessage exchangeMessage(ISAKMPMessage messageToSend) throws IOException, ISAKMPParsingException {
        if (!udpTH.isInitialized()) {
            udpTH.initialize();
        }
        if (initiatorCookie == null) {
            initiatorCookie = messageToSend.getInitiatorCookie();
        } else {
            messageToSend.setInitiatorCookie(initiatorCookie);
        }
        if (responderCookie != null) {
            messageToSend.setResponderCookie(responderCookie);
        }
        udpTH.sendData(messageToSend.getBytes());
        byte[] rxData = udpTH.fetchData();
        if (rxData.length == 0) {
            throw new IOException("No data received within timeout");
        }
        ISAKMPMessage messageReceived = IKEv1MessageBuilder.fromByteArray(rxData);
        responderCookie = messageReceived.getResponderCookie();
        return messageReceived;
    }

    public void dispose() throws IOException {
        if (udpTH.isInitialized()) {
            udpTH.closeConnection();
        }
    }

    public KeyExchangePayload prepareKeyExchangePayload() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        if (keyPair == null) {
            KeyPairGenerator keyPairGen;
            if (group.isEC()) {
                keyPairGen = KeyPairGenerator.getInstance("EC");
            } else {
                keyPairGen = KeyPairGenerator.getInstance("DiffieHellman");
            }
            keyPairGen.initialize(group.getAlgorithmParameterSpec());
            keyPair = keyPairGen.generateKeyPair();
        }
        KeyExchangePayload result = new KeyExchangePayload();
        result.setKeyExchangeData(keyPair.getPublic().getEncoded());
        return result;
    }

    public IdentificationPayload prepareIdentificationPayload() throws IOException {
        if (!udpTH.isInitialized()) {
            udpTH.initialize();
        }
        InetAddress addr = udpTH.getLocalAddress();
        IdentificationPayload result = new IdentificationPayload();
        if (addr instanceof Inet6Address) {
            result.setIdType(IDTypeEnum.ID_IPV6_ADDR);
            result.setIdentificationData(addr.getAddress());
        } else if (addr instanceof Inet4Address) {
            result.setIdType(IDTypeEnum.ID_IPV4_ADDR);
            result.setIdentificationData(addr.getAddress());
        }
        return result;
    }

}
