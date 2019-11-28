/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.StringJoiner;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class ISAKMPMessage implements ISAKMPSerializable {

    public static final int ISAKMP_HEADER_LEN = 28;

    private byte[] initiatorCookie;
    private byte[] responderCookie = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private byte version = 0x10;
    private ExchangeTypeEnum exchangeType = ExchangeTypeEnum.NONE;
    private final BitSet flags = new BitSet(3);
    private byte[] messageId = new byte[]{0x00, 0x00, 0x00, 0x00};
    protected final List<ISAKMPPayload> payloads = new ArrayList<>();

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
        if (bytes.length > 1 || bytes[0] > 0x07) {
            throw new IllegalStateException("Too many flags");
        }
        return bytes[0];
    }

    public final void setEncryptedFlag(boolean value) {
        this.flags.set(0, value);
    }

    public final void setCommitFlag(boolean value) {
        this.flags.set(1, value);
    }

    public final void setAuthenticationOnlyFlag(boolean value) {
        this.flags.set(2, value);
    }

    public boolean isEncryptedFlag() {
        return this.flags.get(0);
    }

    public boolean isCommitFlag() {
        return this.flags.get(1);
    }

    public boolean isAuthenticationOnlyFlag() {
        return this.flags.get(2);
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

    public List<ISAKMPPayload> getPayloads() {
        return Collections.unmodifiableList(payloads);
    }

    public void addPayload(ISAKMPPayload payload) {
        if (!payloads.isEmpty()) {
            payloads.get(payloads.size() - 1).setNextPayload(payload.getType());
        }
        payload.setNextPayload(PayloadTypeEnum.NONE);
        payloads.add(payload);
    }

    public void addPayload(int index, ISAKMPPayload payload) {
        payloads.add(index, payload);
        updateNextPayloadProperty();
    }

    protected void updateNextPayloadProperty() {
        for (int i = 0; i < payloads.size(); i++) {
            ISAKMPPayload payload = payloads.get(i);
            if (i < payloads.size() - 1) {
                ISAKMPPayload nextPayload = payloads.get(i + 1);
                payload.setNextPayload(nextPayload.getType());
            } else {
                payload.setNextPayload(PayloadTypeEnum.NONE);
            }
        }
    }

    public PayloadTypeEnum getNextPayload() {
        if (payloads.isEmpty()) {
            return PayloadTypeEnum.NONE;
        }
        return payloads.get(0).getType();
    }

    @Override
    public int getLength() {
        int length = ISAKMP_HEADER_LEN;
        for (ISAKMPPayload payload : payloads) {
            length += payload.getLength();
        }
        return length;
    }

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
        payloads.forEach((payload) -> {
            payload.writeBytes(baos);
        });
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        writeBytesWithoutPayloads(baos);
        writeBytesOfPayloads(baos);
    }

    public byte[] getBytes() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        writeBytes(baos);
        return baos.toByteArray();
    }

    @Override
    public String toString() {
        StringBuilder name = new StringBuilder();
        if (this.getVersion() == 0x10) {
            name.append("v1");
        } else {
            name.append("v2");
        }
        name.append("_");
        switch (this.getExchangeType()) {
            case IdentityProtection:
                name.append("MM");
                break;
            case Aggressive:
                name.append("AM");
                break;
            case QuickMode:
                name.append("QM");
                break;
            case Informational:
                name.append("INFO");
                break;
            default:
                throw new UnsupportedOperationException("Not supported yet.");
        }
        if (this.isEncryptedFlag()) {
            name.append("*");
        }
        name.append("_");
        StringJoiner payloadSequence = new StringJoiner("-");
        this.getPayloads().forEach((payload) -> {
            payloadSequence.add(payload.toString());
        });
        name.append(payloadSequence.toString());
        return name.toString();
    }
}
