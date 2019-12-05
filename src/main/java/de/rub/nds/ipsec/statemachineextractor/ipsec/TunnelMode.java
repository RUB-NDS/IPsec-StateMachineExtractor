/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ipsec;

import com.savarese.rocksaw.net.RawSocket;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.SocketException;
import java.util.Arrays;
import org.savarese.vserv.tcpip.IPPacket;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class TunnelMode {

    protected RawSocket socket;
    private final long timeout;
    private final InetAddress localAddress, remoteAddress;

    public TunnelMode(InetAddress localAddress, InetAddress remoteAddress, int timeout) throws IOException {
        this.timeout = timeout;
        this.localAddress = localAddress;
        this.remoteAddress = remoteAddress;
        this.socket = new RawSocket();
        if (localAddress instanceof Inet6Address && remoteAddress instanceof Inet6Address) {
            this.socket.open(RawSocket.PF_INET6, ESPMessage.PROTOCOL_NUMBER_ESP);
        } else if (localAddress instanceof Inet4Address && remoteAddress instanceof Inet4Address) {
            this.socket.open(RawSocket.PF_INET, ESPMessage.PROTOCOL_NUMBER_ESP);
        } else {
            throw new UnsupportedOperationException("Not supported yet!");
        }
        try {
            socket.setSendTimeout(timeout);
            socket.setReceiveTimeout(timeout);
        } catch (final SocketException se) {
            socket.setUseSelectTimeout(true);
            socket.setSendTimeout(timeout);
            socket.setReceiveTimeout(timeout);
        }
    }

    public void send(IPPacket packet) throws IOException {
        byte[] data = new byte[packet.getIPPacketLength()];
        packet.getData(data);
        this.socket.write(remoteAddress, data);
    }

    public IPPacket receive() throws IOException {
        byte[] buffer = new byte[20000];
        int length = socket.read(buffer);
        IPPacket pkt = new IPPacket(length);
        pkt.setData(Arrays.copyOf(buffer, length));
        return pkt;
    }
}
