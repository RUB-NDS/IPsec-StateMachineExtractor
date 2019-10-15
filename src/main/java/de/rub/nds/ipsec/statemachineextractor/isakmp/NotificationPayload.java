/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import static de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPPayload.read4ByteFromStream;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class NotificationPayload extends ISAKMPPayload {

    protected static final int NOTIFICATION_HEADER_LEN = 12;

    private int domainOfInterpretation = 0x01; //IPSEC
    private byte protocolID = 0x01; //ISAKMP
    private byte[] spi = new byte[0];
    private NotifyMessageTypeEnum notifyMessageType = NotifyMessageTypeEnum.InvalidPayloadType;
    private byte[] notificationData = new byte[0];

    public NotificationPayload() {
        super(PayloadTypeEnum.Notification);
    }

    public int getDomainOfInterpretation() {
        return domainOfInterpretation;
    }

    public void setDomainOfInterpretation(int domainOfInterpretation) {
        this.domainOfInterpretation = domainOfInterpretation;
    }

    public byte getProtocolID() {
        return protocolID;
    }

    public void setProtocolID(byte protocolID) {
        this.protocolID = protocolID;
    }

    public byte getSpiSize() {
        return (byte) spi.length;
    }

    public byte[] getSpi() {
        return spi;
    }

    public void setSpi(byte[] spi) {
        if (spi.length > 16) {
            throw new IllegalArgumentException("Security Parameter Index (SPI) length may be from zero (0) to sixteen (16)");
        }
        this.spi = spi;
    }

    public byte[] getNotificationData() {
        return notificationData;
    }

    public void setNotificationData(byte[] notificationData) {
        this.notificationData = notificationData;
    }

    public NotifyMessageTypeEnum getNotifyMessageType() {
        return notifyMessageType;
    }

    public void setNotifyMessageType(NotifyMessageTypeEnum notifyMessageType) {
        this.notifyMessageType = notifyMessageType;
    }

    @Override
    public String toString() {
        return this.notifyMessageType.toString();
    }

    @Override
    public int getLength() {
        return NOTIFICATION_HEADER_LEN + spi.length + notificationData.length;
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        super.writeBytes(baos);
        baos.write(DatatypeHelper.intTo4ByteArray(domainOfInterpretation), 0, 4);
        baos.write(protocolID);
        baos.write(getSpiSize());
        baos.write(notifyMessageType.getValue(), 0, 2);
        baos.write(spi, 0, spi.length);
        baos.write(notificationData, 0, notificationData.length);
    }

    public static NotificationPayload fromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        NotificationPayload notificationPayload = new NotificationPayload();
        notificationPayload.fillFromStream(bais);
        return notificationPayload;
    }

    @Override
    protected void fillFromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        int length = this.fillGenericPayloadHeaderFromStream(bais);
        this.setDomainOfInterpretation(ByteBuffer.wrap(read4ByteFromStream(bais)).getInt());
        byte[] buffer = read4ByteFromStream(bais);
        this.setProtocolID(buffer[0]);
        this.setNotifyMessageType(NotifyMessageTypeEnum.get(Arrays.copyOfRange(buffer, 2, 4)));
        if (buffer[1] > 16 || buffer[1] < 0) {
            throw new ISAKMPParsingException("Security Parameter Index (SPI) length may be from zero (0) to sixteen (16)");
        }
        if (buffer[1] > 0) {
            byte[] spidata = new byte[buffer[1]];
            int readBytes;
            try {
                readBytes = bais.read(spidata);
            } catch (IOException ex) {
                throw new ISAKMPParsingException(ex);
            }
            if (readBytes != spidata.length) {
                throw new ISAKMPParsingException("Input stream ended early after " + readBytes + " bytes (should read " + spidata.length + "bytes)!");
            }
            this.setSpi(spidata);
        }
        buffer = new byte[length - NOTIFICATION_HEADER_LEN - buffer[1]];
        if (buffer.length > 0) {
            int readBytes;
            try {
                readBytes = bais.read(buffer);
            } catch (IOException ex) {
                throw new ISAKMPParsingException(ex);
            }
            if (readBytes != buffer.length) {
                throw new ISAKMPParsingException("Input stream ended early after " + readBytes + " bytes (should read " + buffer.length + "bytes)!");
            }
            this.setNotificationData(buffer);
        }
    }

    @Override
    protected void setBody(byte[] body) throws ISAKMPParsingException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

}
