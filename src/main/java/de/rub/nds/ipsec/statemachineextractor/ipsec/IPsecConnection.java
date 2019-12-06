/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ipsec;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.IKEv1Handshake;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.SecurityAssociationSecrets;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.DHGroupAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ProtocolIDEnum;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import de.rub.nds.ipsec.statemachineextractor.util.IPProtocolsEnum;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Random;
import org.savarese.vserv.tcpip.TCPPacket;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public final class IPsecConnection {
    
    private IKEv1Handshake handshake;
    private final int timeout;
    private final InetAddress localAddress, remoteAddress;
    private final int remotePort;
    private SecurityAssociationSecrets SA;
    private TunnelMode tunnel;

    public IPsecConnection(InetAddress remoteAddress, int remotePort, int timeout) throws IOException, GeneralSecurityException {
        this.timeout = timeout;
        this.remoteAddress = remoteAddress;
        try (final DatagramSocket socket = new DatagramSocket()) {
            socket.connect(remoteAddress, remotePort);
            this.localAddress = socket.getLocalAddress();
        }
        this.remotePort = remotePort;
        this.handshake = new IKEv1Handshake(timeout, remoteAddress, remotePort);
        this.SA = new SecurityAssociationSecrets(DHGroupAttributeEnum.GROUP1);
        this.SA.setProtocol(ProtocolIDEnum.IPSEC_ESP);
        this.SA.setInboundSpi(DatatypeHelper.intTo4ByteArray(new Random().nextInt()));
        this.SA.setOutboundSpi(DatatypeHelper.intTo4ByteArray(new Random().nextInt()));
        this.handshake.computeIPsecKeyMaterial(this.SA);
        this.tunnel = new TunnelMode(localAddress, remoteAddress, SA, timeout);
    }

    public void dispose() throws IOException {
        this.handshake.dispose();
    }

    public void reset() throws IOException, GeneralSecurityException {
        this.dispose();
        this.handshake = new IKEv1Handshake(timeout, remoteAddress, remotePort);
    }

    public IKEv1Handshake getHandshake() {
        return handshake;
    }

    public SecurityAssociationSecrets getSA() {
        return SA;
    }

    public void setSA(SecurityAssociationSecrets SA) {
        this.SA = SA;
    }

    public boolean sendTCPSYNToSSH() throws IOException, GeneralSecurityException {
        int length = 40;
        Random rnd = new Random();
        TCPPacket pkt = new TCPPacket(length);
        pkt.setIPVersion(4);
        pkt.setIPHeaderLength(5);
        pkt.setIPPacketLength(length);
        pkt.setIdentification(rnd.nextInt());
        pkt.setTTL(64);
        pkt.setProtocol(IPProtocolsEnum.TCP.value());
        pkt.setSourceAsWord(ByteBuffer.wrap(localAddress.getAddress()).getInt());
        pkt.setDestinationAsWord(ByteBuffer.wrap(remoteAddress.getAddress()).getInt());
        pkt.computeIPChecksum();
        pkt.setSourcePort(50000 + rnd.nextInt(10000));
        pkt.setDestinationPort(22);
        pkt.setSequenceNumber(rnd.nextInt());
        pkt.setTCPHeaderLength(5);
        pkt.setControlFlags(2); // SYN-Flag set
        pkt.setWindowSize(0x7210); // value captured from a real handshake
        pkt.computeTCPChecksum();
        return this.tunnel.sendAndReceive(pkt) != null;
    }
}
