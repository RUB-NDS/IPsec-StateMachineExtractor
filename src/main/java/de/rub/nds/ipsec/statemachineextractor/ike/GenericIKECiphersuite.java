/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike;

import java.security.GeneralSecurityException;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public abstract class GenericIKECiphersuite {

    protected int nonceLen = 16; // RFC2409: 8 - 256 bytes (inclusive); Huawei works with 16 bytes

    public abstract int getKeySize();
    
    public abstract DHGroupEnum getDhGroup();
    
    public abstract int getCipherBlocksize() throws GeneralSecurityException;

    public int getNonceLen() {
        return nonceLen;
    }

    public void setNonceLen(int nonceLen) {
        this.nonceLen = nonceLen;
    }
}
