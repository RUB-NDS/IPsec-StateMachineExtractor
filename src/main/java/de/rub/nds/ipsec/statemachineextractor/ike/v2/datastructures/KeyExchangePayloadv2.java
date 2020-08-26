/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures;

import de.rub.nds.ipsec.statemachineextractor.ike.DHGroupEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKEParsingException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEPayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.IKEv2ParsingException;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class KeyExchangePayloadv2 extends IKEv2Payload {

    private DHGroupTransformEnum dhGroup;
    protected static final int HEADER_LEN = 8;
    private byte[] keyExchangeData;
    private byte[] body;

    public KeyExchangePayloadv2(DHGroupEnum dhGroup) {
        super(IKEPayloadTypeEnum.KeyExchangev2);
        this.dhGroup = DHGroupTransformEnum.valueOf(dhGroup.name());
    }

    public void setDhGroup(DHGroupTransformEnum dhGroup) {
        this.dhGroup = dhGroup;
    }

    @Override
    public int getLength() {
        int length = HEADER_LEN;
        length += keyExchangeData.length;
        return length;
    }

    public DHGroupTransformEnum getDhGroup() {
        return dhGroup;
    }

    public byte[] getKeyExchangeData() {
        return keyExchangeData;
    }

    public void setKeyExchangeData(byte[] keyExchangeData) {
        this.keyExchangeData = keyExchangeData;
    }

    @Override
    public byte[] getBody() {
        return body;
    }

    public void configureBody() throws IKEv2ParsingException {
        if (dhGroup == null || keyExchangeData == null) {
            throw new IKEv2ParsingException("No dhGroup or KeyExchange Data set!");
        }
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(0x00);
        baos.write(this.dhGroup.getValue());
        baos.write(0x00);
        baos.write(0x00);
        try {
            baos.write(this.getKeyExchangeData());
        } catch (IOException ex) {
            throw new IKEv2ParsingException(ex);
        }
        this.body = baos.toByteArray();
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        super.writeBytes(baos);
        baos.write(this.getBody(), 0, this.body.length);
    }

    @Override
    public String toString() {
        return "KEv2";
    }

    public static KeyExchangePayloadv2 fromStream(ByteArrayInputStream bais) throws GenericIKEParsingException {
        KeyExchangePayloadv2 keyExchangePayload = new KeyExchangePayloadv2(null);
        keyExchangePayload.fillFromStream(bais);
        return keyExchangePayload;
    }

    @Override
    protected void fillFromStream(ByteArrayInputStream bais) throws GenericIKEParsingException {
        int length = this.fillGenericPayloadHeaderFromStream(bais);
        byte[] buffer = read4ByteFromStream(bais);
        this.setDhGroup(DHGroupTransformEnum.get(buffer[1]));
        byte[] buffer1 = new byte[length - HEADER_LEN];
        int readBytes;
        try {
            readBytes = bais.read(buffer1);
        } catch (IOException ex) {
            throw new IKEv2ParsingException(ex);
        }
        if (readBytes < length - HEADER_LEN) {
            throw new IKEv2ParsingException("Input stream ended early after " + readBytes + " bytes (should read " + (length - HEADER_LEN) + " bytes)!");
        }
        this.setKeyExchangeData(buffer1);
        this.configureBody();
    }

    @Override
    protected void setBody(byte[] body) throws IKEv2ParsingException {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
