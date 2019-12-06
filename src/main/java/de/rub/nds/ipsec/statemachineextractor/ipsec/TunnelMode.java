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
import de.rub.nds.ipsec.statemachineextractor.ike.v1.SecurityAssociationSecrets;
import de.rub.nds.ipsec.statemachineextractor.util.IPProtocolsEnum;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.spec.SecretKeySpec;
import static jdk.nashorn.internal.objects.NativeRegExpExecResult.length;
import org.savarese.vserv.tcpip.IPPacket;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class TunnelMode {

    protected RawSocket socket;
    private final InetAddress localAddress, remoteAddress;
    private final SecurityAssociationSecrets secrets;

    public TunnelMode(InetAddress localAddress, InetAddress remoteAddress, SecurityAssociationSecrets sas, int timeout) throws IOException {
        this.localAddress = localAddress;
        this.remoteAddress = remoteAddress;
        this.secrets = sas;
        this.socket = new RawSocket();
        try {
            if (remoteAddress instanceof Inet6Address) {
                throw new UnsupportedOperationException("Not supported yet!");
            } else if (remoteAddress instanceof Inet4Address) {
                this.socket.open(RawSocket.PF_INET, IPProtocolsEnum.ESP.value());
            } else {
                throw new UnsupportedOperationException("Not supported yet!");
            }
        } catch (IOException ex) {
            if (ex.getStackTrace()[0].getMethodName().equals("__throwIOException")) {
                throw new Error("Opening raw socket failed! Most probably your java executable is missing the 'cap_net_raw' capability!", ex);
            }
        }
        try {
            socket.setSendTimeout(timeout);
            socket.setReceiveTimeout(timeout);
        } catch (SocketException se) {
            socket.setUseSelectTimeout(true);
            socket.setSendTimeout(timeout);
            socket.setReceiveTimeout(timeout);
        }
    }

    public IPPacket sendAndReceive(IPPacket packet) throws IOException, GeneralSecurityException {
        byte[] data = new byte[packet.getIPPacketLength()];
        packet.getData(data);
        ESPMessage msg = new ESPMessage(new SecretKeySpec(secrets.getOutboundKeyMaterial(), "AES"), "AES", "CBC");
        msg.setSpi(secrets.getOutboundSpi());
        msg.setSequenceNumber(1);
        msg.setPayloadData(data);
        msg.setNextHeader(IPProtocolsEnum.IPv4.value());
        IPPacket espPacket = msg.getIPPacket(localAddress, remoteAddress);
        int ipHeaderByteLength = espPacket.getIPHeaderByteLength();
        data = new byte[espPacket.getIPPacketLength()];
        espPacket.getData(data);
        this.socket.write(remoteAddress, data, ipHeaderByteLength, data.length - ipHeaderByteLength);
        return this.receive();
    }

    protected IPPacket receive() throws IOException {
        byte[] buffer = new byte[20000];
        try {
            int length = socket.read(buffer);
            IPPacket pkt = new IPPacket(length);
            pkt.setData(Arrays.copyOf(buffer, length));
            return pkt;
        } catch (InterruptedIOException ex) {
            return null; // Timeout
        }
    }
}
