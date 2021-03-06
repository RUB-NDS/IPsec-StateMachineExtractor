/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.networking;

import java.io.IOException;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.Arrays;

/**
 * Taken from: TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH Licensed under
 * Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
public class UdpOutputStream extends OutputStream {

    private final static int BUFFER_SIZE = 8192;

    private final DatagramSocket socket;

    private int index;

    private final byte[] dataBuffer = new byte[BUFFER_SIZE];

    public UdpOutputStream(DatagramSocket socket) {
        this.socket = socket;
    }

    @Override
    public void write(int i) throws IOException {
        dataBuffer[index] = (byte) (i & 0x0ff);
        index++;

        if (index >= dataBuffer.length) {
            flush();
        }
    }

    @Override
    public void close() throws IOException {
        if (!socket.isClosed()) {
            socket.close();
        }
    }

    @Override
    public void flush() throws IOException {
        byte[] outData = Arrays.copyOf(dataBuffer, index);
        DatagramPacket packet = new DatagramPacket(outData, index);
        socket.send(packet);
        index = 0;
    }

}
