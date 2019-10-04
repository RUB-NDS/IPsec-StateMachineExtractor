/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import java.io.ByteArrayOutputStream;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public abstract class EncryptedISAKMPSerializable implements ISAKMPSerializable, EncryptedISAKMPData {

    protected boolean isInSync;
    private final ISAKMPPayload underlyingPayload;
    protected byte[] ciphertext = new byte[0];
    
    public EncryptedISAKMPSerializable(ISAKMPPayload payload) {
        this.underlyingPayload = payload;
        this.isInSync = false;
    }

    @Override
    public boolean isIsInSync() {
        return isInSync;
    }

    @Override
    public ISAKMPPayload getUnderlyingPayload() {
        return underlyingPayload;
    }

    @Override
    public byte[] getCiphertext() {
        if (!isInSync) {
            throw new IllegalStateException("Ciphertext not up to date. Run encrypt() first!");
        }
        return ciphertext.clone();
    }
    
    public byte[] getPlaintextFromUnderlyingPayload() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        this.underlyingPayload.writeBytes(baos);
        return baos.toByteArray();
    }
    

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        baos.write(this.getCiphertext(), 0, ciphertext.length);
    }

    @Override
    public int getLength() {
        return this.getCiphertext().length;
    }
}
