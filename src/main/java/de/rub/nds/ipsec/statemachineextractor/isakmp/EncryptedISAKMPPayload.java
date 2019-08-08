/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import static de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPPayload.ISAKMP_PAYLOAD_HEADER_LEN;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public abstract class EncryptedISAKMPPayload extends ISAKMPPayload {

    protected boolean isInSync;
    private final ISAKMPPayload payloadToBeEncrypted;
    protected byte[] encryptedBody = new byte[0];
    
    public EncryptedISAKMPPayload(ISAKMPPayload payload) {
        super(payload.getType());
        this.payloadToBeEncrypted = payload;
        this.isInSync = false;
    }

    public boolean isIsInSync() {
        return isInSync;
    }

    public ISAKMPPayload getPlainPayload() {
        return payloadToBeEncrypted;
    }

    public byte[] getEncryptedBody() {
        if (!isInSync) {
            throw new IllegalStateException("Encrypted body not up to date. Run encrypt() first!");
        }
        return encryptedBody.clone();
    }
    
    public abstract void encrypt() throws GeneralSecurityException;
    
    public abstract void decrypt() throws GeneralSecurityException, ISAKMPParsingException;

    @Override
    protected int fillGenericPayloadHeaderFromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        return payloadToBeEncrypted.fillGenericPayloadHeaderFromStream(bais);
    }

    @Override
    protected byte[] getGenericPayloadHeader() {
        return super.getGenericPayloadHeader();
    }

    @Override
    public void setNextPayload(PayloadTypeEnum nextPayload) {
        payloadToBeEncrypted.setNextPayload(nextPayload);
    }

    @Override
    public PayloadTypeEnum getNextPayload() {
        return payloadToBeEncrypted.getNextPayload();
    }

    @Override
    public PayloadTypeEnum getType() {
        return payloadToBeEncrypted.getType();
    }

    @Override
    public byte[] getBody() {
        return payloadToBeEncrypted.getBody();
    }

    @Override
    protected void setBody(byte[] body) throws ISAKMPParsingException {
        payloadToBeEncrypted.setBody(body);
    }
        
    @Override
    protected void fillFromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        payloadToBeEncrypted.fillFromStream(bais);
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        if (!isInSync) {
            throw new IllegalStateException("Encrypted body not up to date. Run encrypt() first!");
        }
        super.writeBytes(baos);
        baos.write(encryptedBody, 0, encryptedBody.length);
    }

    @Override
    public int getLength() {
        if (!isInSync) {
            throw new IllegalStateException("Encrypted body not up to date. Run encrypt() first!");
        }
        return ISAKMP_PAYLOAD_HEADER_LEN + encryptedBody.length;
    }   
}
