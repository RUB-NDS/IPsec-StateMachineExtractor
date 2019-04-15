/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.util;

import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.udp.stream.UdpInputStream;
import de.rub.nds.tlsattacker.transport.udp.stream.UdpOutputStream;
import java.io.IOException;
import java.io.PushbackInputStream;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;

/**
 * Copied from:
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Extended to add getters and query the socket for data.
 */
public class LoquaciousClientUdpTransportHandler extends TransportHandler {

    private final String hostname;
    private final int port;

    private DatagramSocket socket;

    public LoquaciousClientUdpTransportHandler(Connection connection) {
        super(connection.getTimeout(), ConnectionEndType.CLIENT);
        this.hostname = connection.getHostname();
        this.port = connection.getPort();
    }

    public LoquaciousClientUdpTransportHandler(long timeout, String hostname, int port) {
        super(timeout, ConnectionEndType.CLIENT);
        this.hostname = hostname;
        this.port = port;
    }

    @Override
    public void closeConnection() throws IOException {
        socket.close();
        inStream.close();
        outStream.close();
    }

    @Override
    public void initialize() throws IOException {
        socket = new DatagramSocket();
        socket.connect(new InetSocketAddress(hostname, port));
        socket.setSoTimeout((int) getTimeout());
        setStreams(new PushbackInputStream(new UdpInputStream(socket)), new UdpOutputStream(socket));
    }

    public int getLocalPort() throws IOException {
        return getLocalSocketAddress().getPort();
    }
    
    public InetAddress getLocalAddress() throws IOException {
        return getLocalSocketAddress().getAddress();
    }
    
    public InetSocketAddress getLocalSocketAddress() throws IOException {
        if (socket.isConnected()) {
            SocketAddress localSocketAddress = socket.getLocalSocketAddress();
            if(!(localSocketAddress instanceof InetSocketAddress)) {
                throw new IOException("You're using a weird implementation of java.net");
            }
            return (InetSocketAddress)localSocketAddress;
        }
        throw new IOException("Cannot retrieve local Address. Socket not connected");
    }

    @Override
    public boolean isClosed() throws IOException {
        return socket.isClosed();
    }

    @Override
    public void closeClientConnection() throws IOException {
        closeConnection();
    }
}