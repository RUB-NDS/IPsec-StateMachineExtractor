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
public interface ISAKMPSerializable {

    /**
     * @return the length of the full payload, including the generic payload
     * header
     */
    int getLength();

    void writeBytes(ByteArrayOutputStream baos);
    
    default byte[] getBytes() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        this.writeBytes(baos);
        return baos.toByteArray();
    }
}
