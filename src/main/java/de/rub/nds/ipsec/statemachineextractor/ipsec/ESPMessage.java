/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ipsec;

import de.rub.nds.ipsec.statemachineextractor.SerializableMessage;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import de.rub.nds.ipsec.statemachineextractor.util.IPProtocolsEnum;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Random;
import java.util.StringJoiner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.savarese.vserv.tcpip.IPPacket;
import org.savarese.vserv.tcpip.TCPPacket;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class ESPMessage implements SerializableMessage {

    public static final int IPv4_HEADER_LENGTH = 20;
    public static final int MAC_LENGTH = 12; // 96 bit

    private byte[] spi;
    private int sequenceNumber;
    private byte[] paddedPayloadData;
    private byte[] authenticationData = new byte[0];
    private byte nextHeader;
    private boolean isInSync = false;
    private final Cipher cipher;
    private final Mac mac;
    private final SecretKey secretKey, authKey;
    private IvParameterSpec IV;
    private byte[] ciphertext;

    public ESPMessage(SecretKey secretKey, String algo, String mode) throws GeneralSecurityException {
        this(secretKey, algo, mode, null, null, null);
    }

    public ESPMessage(SecretKey secretKey, String algo, String mode, SecretKey authKey, String mac) throws GeneralSecurityException {
        this(secretKey, algo, mode, null, authKey, mac);
    }

    protected ESPMessage(SecretKey secretKey, String algo, String mode, byte[] IV, SecretKey authKey, String mac) throws GeneralSecurityException {
        this.secretKey = secretKey;
        this.authKey = authKey;
        this.cipher = Cipher.getInstance(algo + "/" + mode + "/NoPadding");
        if (IV == null) {
            byte[] iv = new byte[cipher.getBlockSize()];
            Random rng = new Random();
            rng.nextBytes(iv);
            this.IV = new IvParameterSpec(iv);
        } else {
            this.IV = new IvParameterSpec(IV);
        }
        if (mac != null) {
            this.mac = Mac.getInstance(mac);
        } else {
            this.mac = null;
        }
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        baos.write(spi, 0, 4);
        baos.write(DatatypeHelper.intTo4ByteArray(sequenceNumber), 0, 4);
        baos.write(this.IV.getIV(), 0, this.IV.getIV().length);
        if (!isInSync) {
            try {
                this.encrypt();
            } catch (GeneralSecurityException ex) {
                throw new RuntimeException(ex);
            }
        }
        baos.write(this.ciphertext, 0, this.ciphertext.length);
        baos.write(this.authenticationData, 0, this.authenticationData.length);
    }

    public IPPacket getIPPacket(InetAddress localAddress, InetAddress remoteAddress) throws GeneralSecurityException {
        byte[] espBytes = this.getBytes();
        if (remoteAddress instanceof Inet6Address) {
            throw new UnsupportedOperationException("Not supported yet!");
        } else if (remoteAddress instanceof Inet4Address) {
            int length = espBytes.length + IPv4_HEADER_LENGTH;
            IPPacket pkt = new IPPacket(length);
            pkt.setIPVersion(4);
            pkt.setIPHeaderLength(5);
            pkt.setIPPacketLength(length);
            pkt.setIdentification(new Random().nextInt());
            pkt.setTTL(255);
            pkt.setProtocol(IPProtocolsEnum.ESP.value());
            pkt.setSourceAsWord(ByteBuffer.wrap(localAddress.getAddress()).getInt());
            pkt.setDestinationAsWord(ByteBuffer.wrap(remoteAddress.getAddress()).getInt());
            pkt.computeIPChecksum();
            byte[] data = new byte[length];
            pkt.getData(data);
            System.arraycopy(espBytes, 0, data, IPv4_HEADER_LENGTH, espBytes.length);
            pkt.setData(data);
            return pkt;
        }
        throw new UnsupportedOperationException("Not supported yet!");
    }

    protected void decrypt() throws GeneralSecurityException {
        cipher.init(Cipher.DECRYPT_MODE, secretKey, IV);
        this.paddedPayloadData = cipher.doFinal(this.ciphertext);
        this.isInSync = true;
    }

    protected void encrypt() throws GeneralSecurityException {
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, IV);
        this.paddedPayloadData[paddedPayloadData.length - 1] = nextHeader;
        this.ciphertext = cipher.doFinal(this.paddedPayloadData);
        if (mac != null) {
            mac.init(authKey);
            mac.update(spi, 0, 4);
            mac.update(DatatypeHelper.intTo4ByteArray(sequenceNumber), 0, 4);
            mac.update(this.IV.getIV(), 0, this.IV.getIV().length);
            byte[] macBytes = mac.doFinal(this.ciphertext);
            this.authenticationData = Arrays.copyOf(macBytes, MAC_LENGTH);
        }
        this.isInSync = true;
    }

    protected byte[] addRFC2406Padding(byte[] in) {
        int inOff = in.length;
        int targetByteLength = ((int) Math.ceil((float) (in.length + 1) / cipher.getBlockSize())) * cipher.getBlockSize();
        if ((in.length + 1) % cipher.getBlockSize() == 0) {
            targetByteLength += cipher.getBlockSize();
        }
        byte[] out = new byte[targetByteLength];
        System.arraycopy(in, 0, out, 0, in.length);
        byte code = 1;
        while (inOff < targetByteLength - 2) {
            out[inOff++] = code++;
        }
        out[inOff] = (byte) (code - 1);
        return out;
    }

    protected byte[] removeRFC2406Padding(byte[] in) throws BadPaddingException, IllegalBlockSizeException {
        if (in.length % cipher.getBlockSize() != 0) {
            throw new IllegalBlockSizeException();
        }
        byte padLength = in[in.length - 2];
        if (padLength > cipher.getBlockSize() || padLength < 0) {
            throw new BadPaddingException();
        }
        int i = padLength;
        while (i > 1) {
            if (in[in.length - 3 - (padLength - i)] != i) {
                throw new BadPaddingException();
            }
            i--;
        }
        byte[] out = new byte[in.length - padLength - 2];
        System.arraycopy(in, 0, out, 0, in.length - padLength - 2);
        return out;
    }

    public byte[] getSpi() {
        return spi.clone();
    }

    public void setSpi(byte[] spi) {
        if (spi.length != 4) {
            throw new IllegalArgumentException("The SPI has to be 4 bytes long!");
        }
        this.spi = spi.clone();
    }

    public int getSequenceNumber() {
        return sequenceNumber;
    }

    public void setSequenceNumber(int sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }

    public byte[] getPayloadData() throws BadPaddingException, IllegalBlockSizeException {
        return this.removeRFC2406Padding(this.paddedPayloadData);
    }

    public void setPayloadData(byte[] payloadData) {
        this.paddedPayloadData = this.addRFC2406Padding(payloadData.clone());
        this.isInSync = false;
    }

    public byte[] getAuthenticationData() {
        return authenticationData.clone();
    }

    public void setAuthenticationData(byte[] authenticationData) {
        this.authenticationData = authenticationData.clone();
    }

    public byte getPadLength() {
        return this.paddedPayloadData[this.paddedPayloadData.length - 2];
    }

    public byte getNextHeader() {
        return nextHeader;
    }

    public void setNextHeader(byte nextHeader) {
        this.nextHeader = nextHeader;
        this.isInSync = false;
    }

    public boolean isInSync() {
        return isInSync;
    }

    public byte[] getCiphertext() {
        return ciphertext.clone();
    }

    public void setCiphertext(byte[] ciphertext) {
        if (ciphertext.length % cipher.getBlockSize() != 0) {
            throw new IllegalArgumentException("Ciphertext has to be a multiple of the cipher's block size!");
        }
        this.ciphertext = ciphertext.clone();
        this.isInSync = false;
    }

    public static ESPMessage fromBytes(byte[] msgBytes, SecretKey secretKey, String algo, String mode, SecretKey authKey, String mac) throws GeneralSecurityException, IOException {
        ByteArrayInputStream bais = new ByteArrayInputStream(msgBytes);
        ESPMessage result = new ESPMessage(secretKey, algo, mode, authKey, mac);
        result.setSpi(DatatypeHelper.read4ByteFromStream(bais));
        result.setSequenceNumber(ByteBuffer.wrap(DatatypeHelper.read4ByteFromStream(bais)).getInt());
        byte[] iv = new byte[result.cipher.getBlockSize()];
        bais.read(iv);
        result.IV = new IvParameterSpec(iv);
        if (result.mac == null) {
            result.ciphertext = new byte[bais.available()];
            bais.read(result.ciphertext);
        } else {
            result.ciphertext = new byte[bais.available() - MAC_LENGTH];
            bais.read(result.ciphertext);
            result.authenticationData = new byte[MAC_LENGTH];
            bais.read(result.authenticationData);
            //TODO: Verify authenticationData
        }
        result.decrypt();
        result.setNextHeader(result.paddedPayloadData[result.paddedPayloadData.length - 1]);
        return result;
    }

    @Override
    public String toString() {
        StringJoiner name = new StringJoiner("_");
        name.add("ESP");
        name.add(IPProtocolsEnum.byNumber(nextHeader).name());
        byte[] payloadData;
        try {
            payloadData = this.getPayloadData();
        } catch (BadPaddingException | IllegalBlockSizeException ex) {
            return "ESP_DECRYPT_FAILED";
        }
        name.add(IPProtocolsEnum.byNumber(payloadData[IPPacket.OFFSET_PROTOCOL]).name());
        if (IPProtocolsEnum.byNumber(payloadData[IPPacket.OFFSET_PROTOCOL]) == IPProtocolsEnum.TCP) {
            TCPPacket tcpPacket = new TCPPacket(1);
            tcpPacket.setData(Arrays.copyOfRange(payloadData, IPv4_HEADER_LENGTH, payloadData.length));
            StringBuilder flags = new StringBuilder();
            if (tcpPacket.isSet(TCPPacket.MASK_SYN)) {
                flags.append("SYN");
            }
            if (tcpPacket.isSet(TCPPacket.MASK_ACK)) {
                flags.append("ACK");
            }
            if (tcpPacket.isSet(TCPPacket.MASK_FIN)) {
                flags.append("FIN");
            }
            name.add(flags.toString());
            //TODO: Examine port and retrieve protocol
        }
        //TODO: Details if a UDP packet is payload
        return name.toString();
    }

}
