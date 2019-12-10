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
import static de.rub.nds.ipsec.statemachineextractor.ipsec.ESPMessage.IPv4_HEADER_LENGTH;
import de.rub.nds.ipsec.statemachineextractor.ipsec.attributes.KeyLengthAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
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
import org.savarese.vserv.tcpip.IPPacket;
import org.slf4j.LoggerFactory;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class TunnelMode {

    protected RawSocket socket;
    private final InetAddress localAddress, remoteAddress;
    private final SecurityAssociationSecrets secrets;
    private final ESPTransformIDEnum cipher;
    private final int keySize;
    private int nextOutboundSequenceNumber = 1;
    private Integer nextInboundSequenceNumber;
    private final SecretKeySpec outboundKey, inboundKey;

    public TunnelMode(InetAddress localAddress, InetAddress remoteAddress, SecurityAssociationSecrets sas, ESPTransformIDEnum cipher, KeyLengthAttributeEnum keylength, int timeout) throws IOException {
        this.localAddress = localAddress;
        this.remoteAddress = remoteAddress;
        this.secrets = sas;
        this.cipher = cipher;
        if (cipher.isIsFixedKeySize()) {
            this.keySize = cipher.getKeySize();
        } else {
            if (keylength == null) {
                throw new IllegalArgumentException("keylength is null!");
            }
            this.keySize = keylength.getKeySize();
        }
        
        byte[] keymat = secrets.getOutboundKeyMaterial();
        if (keymat.length < cipher.getKeySize()) {
            throw new UnsupportedOperationException("Not supported yet!");
        }
        this.outboundKey = new SecretKeySpec(Arrays.copyOf(keymat, this.keySize), cipher.cipherJCEName());
        
        keymat = secrets.getInboundKeyMaterial();
        if (keymat.length < cipher.getKeySize()) {
            throw new UnsupportedOperationException("Not supported yet!");
        }
        this.inboundKey = new SecretKeySpec(Arrays.copyOf(keymat, this.keySize), cipher.cipherJCEName());

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

    public ESPMessage sendAndReceive(IPPacket packet) throws IOException, GeneralSecurityException {
        byte[] pktToSendData = new byte[packet.getIPPacketLength()];
        packet.getData(pktToSendData);
        ESPMessage msgOut = new ESPMessage(outboundKey, cipher.cipherJCEName(), cipher.modeOfOperationJCEName());
        msgOut.setSpi(secrets.getOutboundSpi());
        msgOut.setSequenceNumber(nextOutboundSequenceNumber++);
        msgOut.setPayloadData(pktToSendData);
        msgOut.setNextHeader(IPProtocolsEnum.IPv4.value());
        IPPacket espPacket = msgOut.getIPPacket(localAddress, remoteAddress);
        int ipHeaderByteLength = espPacket.getIPHeaderByteLength();
        byte[] espPktToSendData = new byte[espPacket.getIPPacketLength()];
        espPacket.getData(espPktToSendData);
        this.socket.write(remoteAddress, espPktToSendData, ipHeaderByteLength, espPktToSendData.length - ipHeaderByteLength);
        IPPacket unparsedPkt = this.receiveUnparsed();
        byte[] rcvdEspPktDataWithIPHeader = new byte[unparsedPkt.getIPPacketLength()];
        unparsedPkt.getData(rcvdEspPktDataWithIPHeader);
        byte [] rcvdEspPktData = Arrays.copyOfRange(rcvdEspPktDataWithIPHeader, IPv4_HEADER_LENGTH, rcvdEspPktDataWithIPHeader.length);
        ESPMessage msgIn = ESPMessage.fromBytes(rcvdEspPktData, inboundKey, cipher.cipherJCEName(), cipher.modeOfOperationJCEName());
        if (!Arrays.equals(msgIn.getSpi(), secrets.getInboundSpi())) {
            LoggerFactory.getLogger(TunnelMode.class).warn("Decryption succeeded, but SPIs do not match; Received {} vs expected {}!", DatatypeHelper.byteArrayToHexDump(msgIn.getSpi()), DatatypeHelper.byteArrayToHexDump(secrets.getInboundSpi()));
        }
        if (nextInboundSequenceNumber == null) {
            nextInboundSequenceNumber = msgIn.getSequenceNumber();
        } else if (nextInboundSequenceNumber != msgIn.getSequenceNumber()) {
            LoggerFactory.getLogger(TunnelMode.class).warn("Received sequence number {}, expected {}!", msgIn.getSequenceNumber(), nextInboundSequenceNumber);
            nextInboundSequenceNumber = msgIn.getSequenceNumber();
        }
        nextInboundSequenceNumber++;
        return msgIn;
    }

    protected IPPacket receiveUnparsed() throws IOException {
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

    void dispose() throws IOException {
        if (socket.isOpen()) {
            socket.close();
        }
    }
}
