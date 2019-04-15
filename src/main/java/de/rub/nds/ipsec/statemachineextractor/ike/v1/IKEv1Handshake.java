/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1;

import de.rub.nds.ipsec.statemachineextractor.isakmp.IDTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPMessage;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPParsingException;
import de.rub.nds.ipsec.statemachineextractor.isakmp.IdentificationPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.KeyExchangePayload;
import de.rub.nds.ipsec.statemachineextractor.util.LoquaciousClientUdpTransportHandler;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv1Handshake {

    LoquaciousClientUdpTransportHandler udpTH;
    private byte[] initiatorCookie, responderCookie;

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

    public void prepareKeyExchangePayload(KeyExchangePayload keyExchangePayload) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public void prepareIdentificationPayload(IdentificationPayload identificationPayload) throws IOException {
        if (!udpTH.isInitialized()) {
            udpTH.initialize();
        }
        InetAddress addr = udpTH.getLocalAddress();
        if (addr instanceof Inet6Address) {
            identificationPayload.setIdType(IDTypeEnum.ID_IPV6_ADDR);
            identificationPayload.setIdentificationData(addr.getAddress());
        } else if (addr instanceof Inet4Address) {
            identificationPayload.setIdType(IDTypeEnum.ID_IPV4_ADDR);
            identificationPayload.setIdentificationData(addr.getAddress());
        }
    }

}
