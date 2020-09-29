/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.networking;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Logger;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Taken and modified from: TLS-Attacker - A Modular Penetration Testing
 * Framework for TLS Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class LoquaciousClientUdpTransportHandlerTest {

    private final InetAddress localhost = InetAddress.getLoopbackAddress();
    private static final Logger LOG = Logger.getLogger(LoquaciousClientUdpTransportHandlerTest.class.getName());

    @Test
    public void testSendData() throws Exception {
        try (DatagramSocket testSocket = new DatagramSocket()) {
            LoquaciousClientUdpTransportHandler udpTH = new LoquaciousClientUdpTransportHandler(1, localhost.getHostName(),
                    testSocket.getLocalPort());
            testSocket.setSoTimeout(1);

            udpTH.initialize();

            byte[] txData = new byte[8192];
            new Random().nextBytes(txData);
            byte[] rxData = new byte[8192];
            DatagramPacket rxPacket = new DatagramPacket(rxData, rxData.length, localhost, testSocket.getLocalPort());

            udpTH.sendData(txData);
            testSocket.receive(rxPacket);

            assertEquals("Confirm size of the sent data", txData.length, rxPacket.getLength());
            assertArrayEquals("Confirm sent data equals received data", txData, rxPacket.getData());

            udpTH.closeConnection();
        }
    }

    @Test
    public void testFetchData() throws Exception {
        try (DatagramSocket testSocket = new DatagramSocket()) {
            LoquaciousClientUdpTransportHandler udpTH = new LoquaciousClientUdpTransportHandler(100, localhost.getHostName(), testSocket.getLocalPort());

            udpTH.initialize();
            testSocket.connect(localhost, udpTH.getLocalPort());

            byte[] allSentData = new byte[0];
            byte[] allReceivedData = new byte[0];
            byte[] txData;
            byte[] rxData;
            DatagramPacket txPacket;
            int numTestPackets = 100;

            for (int i = 0; i < numTestPackets; i++) {
                txData = new byte[new Random().nextInt(16383) + 1];
                new Random().nextBytes(txData);
                txPacket = new DatagramPacket(txData, txData.length, localhost, udpTH.getLocalPort());
                testSocket.send(txPacket);
                allSentData = concatenate(allSentData, txData);
                rxData = udpTH.fetchData();
                allReceivedData = concatenate(allReceivedData, rxData);
            }
            assertEquals("Confirm size of the received data", allSentData.length, allReceivedData.length);
            assertArrayEquals("Confirm received data equals sent data", allSentData, allReceivedData);

            udpTH.closeConnection();
        }
    }

    @Test
    public void testFetchTimeout() throws Exception {
        LoquaciousClientUdpTransportHandler udpTH = new LoquaciousClientUdpTransportHandler(100, localhost.getHostName(), 12345);
        udpTH.initialize();

        byte[] rxData;
        long startTime = System.currentTimeMillis();
        try {
            rxData = udpTH.fetchData();
            assertEquals(0, rxData.length);
            rxData = udpTH.fetchData();
            assertEquals(0, rxData.length);
        } catch (Exception ex) {
            LOG.severe("You seem to use a TLS-Attacker version <3.0. There are known bugs with the UdpInputStream in these versions, please use an up-to-date TLS-Attacker version!");
            throw ex;
        }
        long endTime = System.currentTimeMillis();
        assertTrue(endTime - startTime >= 200);
        udpTH.closeConnection();
    }
    
    @Test
    public void testNonGreedyness() throws Exception {
        try (DatagramSocket testSocket = new DatagramSocket()) {
            LoquaciousClientUdpTransportHandler udpTH = new LoquaciousClientUdpTransportHandler(1000, localhost.getHostName(), testSocket.getLocalPort());

            udpTH.initialize();
            testSocket.connect(localhost, udpTH.getLocalPort());

            byte[] allSentData = new byte[0];
            byte[] allReceivedData = new byte[0];
            byte[] txData;
            byte[] rxData;
            DatagramPacket txPacket;
            int numTestPackets = 15;

            long startTime = System.currentTimeMillis();
            for (int i = 0; i < numTestPackets; i++) {
                txData = new byte[new Random().nextInt(16383) + 1];
                new Random().nextBytes(txData);
                txPacket = new DatagramPacket(txData, txData.length, localhost, udpTH.getLocalPort());
                testSocket.send(txPacket);
                allSentData = concatenate(allSentData, txData);
                rxData = udpTH.fetchData();
                allReceivedData = concatenate(allReceivedData, rxData);
            }
            long endTime = System.currentTimeMillis();
            assertEquals("Confirm size of the received data", allSentData.length, allReceivedData.length);
            assertArrayEquals("Confirm received data equals sent data", allSentData, allReceivedData);
            assertTrue(endTime - startTime <= 1000);

            udpTH.closeConnection();
        }
    }

    private byte[] concatenate(byte[] a, byte[] b) {
        byte[] result = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

}
