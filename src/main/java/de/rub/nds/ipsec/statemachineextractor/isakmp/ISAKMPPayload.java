/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public abstract class ISAKMPPayload {
    
    private final PayloadTypeEnum type;
    
    public abstract int getLength();
    
    public abstract byte[] getBytes();

    public ISAKMPPayload(PayloadTypeEnum type) {
        this.type = type;
    }

    public PayloadTypeEnum getType() {
        return type;
    }
}
