/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike;

import de.rub.nds.ipsec.statemachineextractor.FixedLengthByteStreamSerializable;
import de.rub.nds.ipsec.statemachineextractor.SerializableMessage;
import de.rub.nds.ipsec.statemachineextractor.ike.ExchangeTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKECiphersuite;
import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKEHandshakeSessionSecrets;
import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKEParsingException;
import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKEPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.HandshakeLongtermSecrets;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEPayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ISAKMPMessage;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.IKEv2Message;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.AbstractMap;
import java.util.BitSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.StringJoiner;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public abstract class IKEMessage implements SerializableMessage, FixedLengthByteStreamSerializable {

    public static final int IKE_MESSAGE_HEADER_LEN = 28;
    public static final int COOKIE_LEN = 8;
    private byte[] initiatorCookie;
    private byte[] responderCookie = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private byte version;
    private ExchangeTypeEnum exchangeType = ExchangeTypeEnum.NONE;
    protected BitSet flags;
    private byte[] messageId = new byte[]{0x00, 0x00, 0x00, 0x00};

    protected IKEMessage(byte version, int numFlags) {
        this.version = version;
        this.flags = new BitSet(numFlags);
    }

    public byte[] getInitiatorCookie() {
        if (initiatorCookie == null) {
            initiatorCookie = new byte[8];
            Random rng = new Random();
            rng.nextBytes(initiatorCookie);
        }
        return initiatorCookie.clone();
    }

    public void setInitiatorCookie(byte[] initiatorCookie) {
        if (initiatorCookie.length != 8) {
            throw new IllegalArgumentException("The Initiator Cookie must be 8 bytes long!");
        }
        this.initiatorCookie = initiatorCookie;
    }

    public byte[] getResponderCookie() {
        return responderCookie.clone();
    }

    public void setResponderCookie(byte[] responderCookie) {
        if (responderCookie.length != 8) {
            throw new IllegalArgumentException("The Responder Cookie must be 8 bytes long!");
        }
        this.responderCookie = responderCookie;
    }

    public byte getVersion() {
        return version;
    }

    public void setVersion(byte version) {
        this.version = version;
    }

    public void setMajorVersion(byte major) {
        if (major > 0x0F) {
            throw new IllegalArgumentException("The Major Version must be 4 bits long!");
        }
        this.version = (byte) ((this.version & 0x0F) | major << 4);
    }

    public void setMinorVersion(byte minor) {
        if (minor > 0x0F) {
            throw new IllegalArgumentException("The Minor Version must be 4 bits long!");
        }
        this.version = (byte) ((this.version & 0xF0) | minor);
    }

    public ExchangeTypeEnum getExchangeType() {
        return exchangeType;
    }

    public void setExchangeType(ExchangeTypeEnum exchangeType) {
        this.exchangeType = exchangeType;
    }

    public byte getFlags() {
        byte[] bytes = this.flags.toByteArray();
        if (bytes.length == 0) {
            return 0x00;
        }
        if (bytes.length > 1) {
            throw new IllegalStateException("Too many flags");
        }
        return bytes[0];
    }

    public byte[] getMessageId() {
        return messageId.clone();
    }

    public void setMessageId(byte[] messageId) {
        if (messageId.length != 4) {
            throw new IllegalArgumentException("The Message ID has to be 4 bytes long!");
        }
        this.messageId = messageId;
    }

    public byte[] setMessageIdRandom() {
        this.messageId = new byte[4];
        Random rng = new Random();
        rng.nextBytes(this.messageId);
        return getMessageId();
    }

    public abstract <T extends GenericIKEPayload> List<T> getPayloads();

    public IKEPayloadTypeEnum getNextPayload() {
        List<GenericIKEPayload> payloads = getPayloads();
        if (payloads.isEmpty()) {
            return IKEPayloadTypeEnum.NONE;
        }
        return payloads.get(0).getType();
    }

    protected void updateNextPayloadProperty() {
        List<GenericIKEPayload> payloads = getPayloads();
        for (int i = 0; i < payloads.size(); i++) {
            GenericIKEPayload payload = payloads.get(i);
            if (i < payloads.size() - 1) {
                GenericIKEPayload nextPayload = payloads.get(i + 1);
                payload.setNextPayload(nextPayload.getType());
            } else {
                payload.setNextPayload(IKEPayloadTypeEnum.NONE);
            }
        }
    }

    protected final Map.Entry<Integer, IKEPayloadTypeEnum> fillHeaderFromStream(ByteArrayInputStream bais) throws GenericIKEParsingException {
        if (bais.available() < IKEMessage.IKE_MESSAGE_HEADER_LEN) {
            throw new GenericIKEParsingException("Not enough bytes supplied to build an IKEMessage!");
        }
        this.initiatorCookie = new byte[COOKIE_LEN];
        bais.read(this.initiatorCookie, 0, COOKIE_LEN);
        bais.read(this.responderCookie, 0, COOKIE_LEN);
        IKEPayloadTypeEnum firstPayload = IKEPayloadTypeEnum.get((byte) bais.read());
        if ((byte) bais.read() != this.version) {
            throw new GenericIKEParsingException("Wrong IKE version!");
        }
        this.exchangeType = ExchangeTypeEnum.get((byte) bais.read());
        this.flags = BitSet.valueOf(new byte[]{(byte) bais.read()});
        bais.read(messageId, 0, messageId.length);
        int messageLength;
        byte[] lengthArray = new byte[4];
        bais.read(lengthArray, 0, lengthArray.length);
        messageLength = new BigInteger(lengthArray).intValue();
        return new AbstractMap.SimpleEntry(messageLength, firstPayload);
        // Non-abstract class has to parse payloads
    }

    public abstract void processFromStream(ByteArrayInputStream bais, GenericIKECiphersuite ciphersuite, GenericIKEHandshakeSessionSecrets secrets, HandshakeLongtermSecrets ltsecrets) throws GenericIKEParsingException, GeneralSecurityException;

    protected void writeBytesWithoutPayloads(ByteArrayOutputStream baos) {
        baos.write(getInitiatorCookie(), 0, 8);
        baos.write(responderCookie, 0, 8);
        baos.write(getNextPayload().getValue());
        baos.write(version);
        baos.write(exchangeType.getValue());
        baos.write(getFlags());
        baos.write(messageId, 0, 4);
        baos.write(DatatypeHelper.intTo4ByteArray(getLength()), 0, 4);
    }

    protected void writeBytesOfPayloads(ByteArrayOutputStream baos) {
        updateNextPayloadProperty();
        getPayloads().forEach((payload) -> {
            payload.writeBytes(baos);
        });
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        writeBytesWithoutPayloads(baos);
        writeBytesOfPayloads(baos);
    }

    @Override
    public int getLength() {
        int length = IKE_MESSAGE_HEADER_LEN;
        for (GenericIKEPayload payload : getPayloads()) {
            length += payload.getLength();
        }
        return length;
    }

    protected abstract void toString(StringBuilder name);

    @Override
    public String toString() {
        StringBuilder name = new StringBuilder();
        switch (this.getVersion()) {
            case ISAKMPMessage.VERSION:
                name.append("v1");
                break;
            case IKEv2Message.VERSION:
                name.append("v2");
                break;
            default:
                throw new UnsupportedOperationException("Not supported yet.");
        }
        name.append("_");
        this.toString(name);
        name.append("_");
        StringJoiner payloadSequence = new StringJoiner("-");
        this.getPayloads().forEach((payload) -> {
            payloadSequence.add(payload.toString());
        });
        name.append(payloadSequence.toString());
        return name.toString();
    }
}
