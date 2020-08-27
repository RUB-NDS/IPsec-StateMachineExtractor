/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class EncryptedPayloadMock extends EncryptedPayload {

    private byte[] presetPadding = new byte[0];

    @Override
    public void genRandomPadding() {
        this.setPadding(presetPadding);
    }

    public byte[] getPresetPadding() {
        return presetPadding;
    }

    public void setPresetPadding(byte[] presetPadding) {
        this.presetPadding = presetPadding;
    }
}
