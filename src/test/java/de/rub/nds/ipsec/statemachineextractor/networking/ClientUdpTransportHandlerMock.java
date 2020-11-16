/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.networking;

import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.io.IOException;
import java.net.InetAddress;
import java.util.HashMap;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class ClientUdpTransportHandlerMock extends LoquaciousClientUdpTransportHandler {

        private byte[] nextResponse;
        private final byte[] localAddress;
        private final HashMap<String, String> msgPairs;

        public ClientUdpTransportHandlerMock(HashMap<String, String> msgPairs, byte[] localAddress) {
            super(0, "localhost", 0);
            this.localAddress = localAddress;
            this.msgPairs = msgPairs;
        }

        @Override
        public InetAddress getLocalAddress() throws IOException {
            return InetAddress.getByAddress(localAddress);
        }

        @Override
        public void initialize() throws IOException {
        }

        @Override
        public void closeConnection() throws IOException {
        }

        @Override
        public boolean isInitialized() {
            return true;
        }

        @Override
        public void sendData(byte[] data) throws IOException {
            final String dataHex = DatatypeHelper.byteArrayToHexDump(data).toLowerCase();
            if (!msgPairs.containsKey(dataHex)) {
                nextResponse = null;
                throw new IOException("Unexpected Message: " + dataHex);
            }
            nextResponse = DatatypeHelper.hexDumpToByteArray(msgPairs.get(dataHex));
        }

        @Override
        public byte[] fetchData() throws IOException {
            return nextResponse;
        }
    }
