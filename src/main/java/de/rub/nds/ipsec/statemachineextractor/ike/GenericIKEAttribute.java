/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike;

import de.rub.nds.ipsec.statemachineextractor.FixedLengthByteStreamSerializable;
import java.io.ByteArrayOutputStream;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public interface GenericIKEAttribute extends FixedLengthByteStreamSerializable {

    final int HEADER_LEN = 4;
    
    byte[] getBytes();

    @Override
    default public void writeBytes(ByteArrayOutputStream baos) {
        baos.write(getBytes(), 0, getLength());
    }

}
