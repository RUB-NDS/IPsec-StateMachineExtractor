/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes;

import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPSerializable;
import java.io.ByteArrayOutputStream;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public interface IKEv1Attribute extends ISAKMPSerializable {

    @Override
    default public int getLength() {
        //TODO: Implement dynamically sized attributes
        return 4;
    }

    @Override
    default public void writeBytes(ByteArrayOutputStream baos) {
        baos.write(getBytes(), 0, getLength());
    }

    public byte[] getBytes();
}
