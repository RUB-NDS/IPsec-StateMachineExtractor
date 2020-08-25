/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v2.payloads;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.PayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPParsingException;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class AuthenticationPayload extends ISAKMPPayload {

    protected static final int ID_HEADER_LEN = 8;

    private AUTHMethodEnum authMethod = AUTHMethodEnum.PSK;
    private final byte[] reserved = new byte[]{0x00, 0x00, 0x00};
    private byte[] authenticationData = new byte[0];

    public AuthenticationPayload() {
        super(PayloadTypeEnum.Authentication);
    }

    public AUTHMethodEnum getAuthMethod() {
        return authMethod;
    }

    public void setAuthMethod(AUTHMethodEnum authMethod) {
        this.authMethod = authMethod;
    }

    public byte[] getAuthenticationData() {
        return authenticationData.clone();
    }

    public void setAuthenticationData(byte[] authenticationData) {
        this.authenticationData = authenticationData;
    }

    @Override
    public String toString() {
        return "AUTH";
    }

    @Override
    public int getLength() {
        return ID_HEADER_LEN + authenticationData.length;
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        super.writeBytes(baos);
        baos.write(authMethod.getValue());
        baos.write(reserved, 0, reserved.length);
        baos.write(authenticationData, 0, authenticationData.length);
    }

    public static AuthenticationPayload fromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        AuthenticationPayload authPayload = new AuthenticationPayload();
        authPayload.fillFromStream(bais);
        return authPayload;
    }

    @Override
    protected void setBody(byte[] body) throws ISAKMPParsingException {
        this.setAuthMethod(AUTHMethodEnum.get(body[0]));
        this.setAuthenticationData(Arrays.copyOfRange(body, 4, body.length));
    }

    @Override
    protected void fillFromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        int length = this.fillGenericPayloadHeaderFromStream(bais);
        byte[] buffer = new byte[length - ISAKMP_PAYLOAD_HEADER_LEN];
        int readBytes;
        try {
            readBytes = bais.read(buffer);
        } catch (IOException ex) {
            throw new ISAKMPParsingException(ex);
        }
        if (readBytes < length - ISAKMP_PAYLOAD_HEADER_LEN) {
            throw new ISAKMPParsingException("Input stream ended early after " + readBytes + " bytes (should read " + (length - ISAKMP_PAYLOAD_HEADER_LEN) + "bytes)!");
        }
        this.setBody(buffer);
    }
}
