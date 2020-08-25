/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ipsec;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.IKEv1Handshake;
import de.rub.nds.ipsec.statemachineextractor.ike.SecurityAssociationSecrets;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.DHGroupAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ipsec.attributes.AuthenticationAlgorithmAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ipsec.attributes.KeyLengthAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ProtocolIDEnum;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import de.rub.nds.ipsec.statemachineextractor.util.IPProtocolsEnum;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import org.savarese.vserv.tcpip.TCPPacket;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public final class IPsecConnection {

    private IKEv1Handshake handshake;
    private final int timeout;
    private final InetAddress localTunnelEndpoint, remoteTunnelEndpoint;
    private final int remotePort;
    private SecurityAssociationSecrets SA;
    private TunnelMode tunnel;

    public IPsecConnection(InetAddress remoteTunnelEndpoint, int remotePort, int timeout) throws IOException, GeneralSecurityException {
        this.timeout = timeout;
        this.remoteTunnelEndpoint = remoteTunnelEndpoint;
        try (final DatagramSocket socket = new DatagramSocket()) {
            socket.connect(remoteTunnelEndpoint, remotePort);
            this.localTunnelEndpoint = socket.getLocalAddress();
        }
        this.remotePort = remotePort;
        this.reset();
    }

    public void dispose() throws IOException {
        if (this.handshake != null) {
            this.handshake.dispose();
        }
        if (this.tunnel != null) {
            this.tunnel.dispose();
        }
    }

    protected void reset() throws IOException, GeneralSecurityException {
        this.dispose();
        this.handshake = new IKEv1Handshake(timeout, remoteTunnelEndpoint, remotePort);
        this.SA = new SecurityAssociationSecrets(DHGroupAttributeEnum.GROUP1.getDHGroupParameters());
        this.SA.setProtocol(ProtocolIDEnum.IPSEC_ESP);
        this.SA.setInboundSpi(DatatypeHelper.intTo4ByteArray(new Random().nextInt()));
        this.SA.setOutboundSpi(DatatypeHelper.intTo4ByteArray(new Random().nextInt()));
        this.handshake.computeIPsecKeyMaterial(this.SA);
        this.tunnel = new TunnelMode(localTunnelEndpoint, remoteTunnelEndpoint, SA, ESPTransformIDEnum.DES, null, null, timeout);
    }

    public IKEv1Handshake getHandshake() {
        return handshake;
    }

    public TunnelMode getTunnel() {
        return tunnel;
    }

    public SecurityAssociationSecrets getSA() {
        return SA;
    }

    public void establishTunnel(SecurityAssociationSecrets SA, ESPTransformIDEnum cipher, KeyLengthAttributeEnum keylength, AuthenticationAlgorithmAttributeEnum authAlgo) throws IOException, NoSuchAlgorithmException {
        this.SA = SA;
        this.tunnel.rekey(SA, cipher, keylength, authAlgo);
    }

    public ESPMessage exchangeTCPSYN(InetAddress localClient, InetAddress remoteServer, int port) throws IOException, GeneralSecurityException {
        int length = 40;
        Random rnd = new Random();
        TCPPacket pkt = new TCPPacket(length);
        pkt.setIPVersion(4);
        pkt.setIPHeaderLength(5);
        pkt.setIPPacketLength(length);
        pkt.setIdentification(rnd.nextInt());
        pkt.setTTL(64);
        pkt.setProtocol(IPProtocolsEnum.TCP.value());
        pkt.setSourceAsWord(ByteBuffer.wrap(localClient.getAddress()).getInt());
        pkt.setDestinationAsWord(ByteBuffer.wrap(remoteServer.getAddress()).getInt());
        pkt.computeIPChecksum();
        pkt.setSourcePort(50000 + rnd.nextInt(10000));
        pkt.setDestinationPort(port);
        pkt.setSequenceNumber(rnd.nextInt());
        pkt.setTCPHeaderLength(5);
        pkt.setControlFlags(2); // SYN-Flag set
        pkt.setWindowSize(0x7210); // value captured from a real handshake
        pkt.computeTCPChecksum();
        return this.tunnel.sendAndReceive(pkt); //TODO: Check if response is TCP, SYN/ACK Flags are set, etc.
    }
}
