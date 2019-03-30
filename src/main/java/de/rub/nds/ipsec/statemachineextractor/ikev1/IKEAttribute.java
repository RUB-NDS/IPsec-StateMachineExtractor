/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ikev1;

import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPSerializable;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.io.ByteArrayOutputStream;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEAttribute implements ISAKMPSerializable {
    
    private final byte[] bytes;

    private IKEAttribute(int bytes) {
        this.bytes = DatatypeHelper.intTo4ByteArray(bytes);
    }
    
    @Override
    public int getLength() {
        return 4;
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        baos.write(bytes, 0, 4);
    }
    
    public static IKEAttribute AES_CBC = new IKEAttribute(0x80010007);
    public static IKEAttribute KEY_LEN_128 = new IKEAttribute(0x800e0080);
    public static IKEAttribute SHA1 = new IKEAttribute(0x80020002);
    public static IKEAttribute DH_GROUP_5 = new IKEAttribute(0x80040005);
    public static IKEAttribute PKE = new IKEAttribute(0x80030004);
    public static IKEAttribute LIFETYPE_SEC = new IKEAttribute(0x800b0001);
    public static IKEAttribute DURATION28800 = new IKEAttribute(0x800c7080);
}
