/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor;

import de.rub.nds.tlsattacker.transport.udp.ClientUdpTransportHandler;
import java.io.IOException;
import java.math.BigInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class Main {
    public static void main(String[] args) {
        ClientUdpTransportHandler udpTH = new ClientUdpTransportHandler(100, "9.9.9.9", 53);
        try {
            udpTH.initialize();
            byte[] txData = new BigInteger("509c0100000100000000000003777777037275620264650000010001", 16).toByteArray();
            udpTH.sendData(txData);
            byte[] rxData = udpTH.fetchData();
            udpTH.closeConnection();
            System.out.println(new BigInteger(1, rxData).toString(16));
        } catch (IOException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
