/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ipsec;

import com.savarese.rocksaw.net.RawSocket;
import de.rub.nds.ipsec.statemachineextractor.ike.SecurityAssociationSecrets;
import static de.rub.nds.ipsec.statemachineextractor.ipsec.ESPMessage.IPv4_HEADER_LENGTH;
import de.rub.nds.ipsec.statemachineextractor.ipsec.attributes.AuthenticationAlgorithmAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ipsec.attributes.KeyLengthAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.util.IPProtocolsEnum;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Mac;
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
    private SecurityAssociationSecrets secrets;
    private ESPTransformIDEnum cipher;
    private AuthenticationAlgorithmAttributeEnum authAlgo;
    private int keySize;
    private int nextOutboundSequenceNumber = 1;
    private Integer nextInboundSequenceNumber;
    SecretKeySpec outboundKeyEnc, inboundKeyEnc, outboundKeyAuth, inboundKeyAuth;

    public TunnelMode(InetAddress localAddress, InetAddress remoteAddress, SecurityAssociationSecrets sas, ESPTransformIDEnum cipher, KeyLengthAttributeEnum keylength, AuthenticationAlgorithmAttributeEnum authAlgo, int timeout) throws IOException, NoSuchAlgorithmException {
        this.localAddress = localAddress;
        this.remoteAddress = remoteAddress;
        this.rekey(sas, cipher, keylength, authAlgo);
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

    public final void rekey(SecurityAssociationSecrets sas, ESPTransformIDEnum cipher, KeyLengthAttributeEnum keylength, AuthenticationAlgorithmAttributeEnum authAlgo) throws NoSuchAlgorithmException {
        if (this.secrets != null && Arrays.equals(this.secrets.getInboundSpi(), sas.getInboundSpi()) && Arrays.equals(this.secrets.getOutboundSpi(), sas.getOutboundSpi())) {
            return;
        }
        this.secrets = sas;
        this.authAlgo = authAlgo;
        this.cipher = cipher;
        if (cipher.isIsFixedKeySize()) {
            this.keySize = cipher.getKeySize();
        } else {
            if (keylength == null) {
                throw new IllegalArgumentException("keylength is null!");
            }
            this.keySize = keylength.getKeySize();
        }

        /*
         * https://tools.ietf.org/html/rfc4306#section-2.17
         * All keys for SAs carrying data from the initiator to the responder
         * are taken before SAs going in the reverse direction. [...]
         * If a single protocol has both encryption and authentication keys,
         * the encryption key is taken from the first octets of KEYMAT and
         * the authentication key is taken from the next octets.
         */
        int macLength = 0;
        byte[] keymat = new byte[this.keySize];
        if (secrets.getOutboundKeyMaterial(keymat) < cipher.getKeySize()) {
            throw new UnsupportedOperationException("Not enough key material!");
        }
        this.outboundKeyEnc = new SecretKeySpec(keymat, cipher.cipherJCEName());
        if (this.authAlgo != null) {
            macLength = Mac.getInstance(this.authAlgo.macJCEName()).getMacLength();
            keymat = new byte[macLength];
            if (secrets.getOutboundKeyMaterial(keymat) < macLength) {
                throw new UnsupportedOperationException("Not enough key material!");
            }
            this.outboundKeyAuth = new SecretKeySpec(keymat, this.authAlgo.macJCEName());
        }

        keymat = new byte[this.keySize];
        if (secrets.getInboundKeyMaterial(keymat) < cipher.getKeySize()) {
            throw new UnsupportedOperationException("Not enough key material!");
        }
        this.inboundKeyEnc = new SecretKeySpec(keymat, cipher.cipherJCEName());
        if (this.authAlgo != null) {
            keymat = new byte[macLength];
            if (secrets.getInboundKeyMaterial(keymat) < macLength) {
                throw new UnsupportedOperationException("Not enough key material!");
            }
            this.inboundKeyAuth = new SecretKeySpec(keymat, this.authAlgo.macJCEName());
        }

        nextOutboundSequenceNumber = 1;
        nextInboundSequenceNumber = 1;
    }

    public ESPMessage sendAndReceive(IPPacket packet) throws IOException, GeneralSecurityException {
        {
            byte[] pktToSendData = new byte[packet.getIPPacketLength()];
            packet.getData(pktToSendData);
            ESPMessage msgOut;
            if (this.authAlgo != null) {
                msgOut = new ESPMessage(outboundKeyEnc, cipher.cipherJCEName(), cipher.modeOfOperationJCEName(), outboundKeyAuth, authAlgo.macJCEName());
            } else {
                msgOut = new ESPMessage(outboundKeyEnc, cipher.cipherJCEName(), cipher.modeOfOperationJCEName());
            }
            msgOut.setSpi(secrets.getOutboundSpi());
            msgOut.setSequenceNumber(nextOutboundSequenceNumber++);
            msgOut.setPayloadData(pktToSendData);
            msgOut.setNextHeader(IPProtocolsEnum.IPv4.value());
            IPPacket espPacket = msgOut.getIPPacket(localAddress, remoteAddress);
            int ipHeaderByteLength = espPacket.getIPHeaderByteLength();
            byte[] espPktToSendData = new byte[espPacket.getIPPacketLength()];
            espPacket.getData(espPktToSendData);
            this.socket.write(remoteAddress, espPktToSendData, ipHeaderByteLength, espPktToSendData.length - ipHeaderByteLength);
        }
        ESPMessage msgIn = null;
        while (msgIn == null) {
            IPPacket unparsedPkt = this.receiveUnparsed();
            if (unparsedPkt == null) {
                return null;
            }
            byte[] rcvdEspPktDataWithIPHeader = new byte[unparsedPkt.getIPPacketLength()];
            unparsedPkt.getData(rcvdEspPktDataWithIPHeader);
            byte[] rcvdEspPktData = Arrays.copyOfRange(rcvdEspPktDataWithIPHeader, IPv4_HEADER_LENGTH, rcvdEspPktDataWithIPHeader.length);
            try {
                if (this.authAlgo != null) {
                    msgIn = ESPMessage.fromBytes(rcvdEspPktData, inboundKeyEnc, cipher.cipherJCEName(), cipher.modeOfOperationJCEName(), inboundKeyAuth, authAlgo.macJCEName());
                } else {
                    msgIn = ESPMessage.fromBytes(rcvdEspPktData, inboundKeyEnc, cipher.cipherJCEName(), cipher.modeOfOperationJCEName(), null, null);
                }
            } catch (GeneralSecurityException ex) {
                msgIn = null; // Decrypt error, probably we received garbage
                continue;
            }
            if (!Arrays.equals(msgIn.getSpi(), secrets.getInboundSpi())) {
                msgIn = null; // SPIs do not match, probably we received a retransmission of an old SPI
            }
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
