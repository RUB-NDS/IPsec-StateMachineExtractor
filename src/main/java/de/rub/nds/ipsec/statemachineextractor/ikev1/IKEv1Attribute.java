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
public class IKEv1Attribute implements ISAKMPSerializable {
    
    private final byte[] bytes;

    protected IKEv1Attribute(int bytes) {
        //TODO: Implement dynamically sized attributes
        this.bytes = DatatypeHelper.intTo4ByteArray(bytes);
    }
    
    @Override
    public int getLength() {
        //TODO: Implement dynamically sized attributes
        return 4;
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        //TODO: Implement dynamically sized attributes
        baos.write(bytes, 0, 4);
    }
    
    public static IKEv1Attribute AES_CBC = new IKEv1Attribute(0x80010007);
    public static IKEv1Attribute KEY_LEN_128 = new IKEv1Attribute(0x800e0080);
    public static IKEv1Attribute SHA1 = new IKEv1Attribute(0x80020002);
    public static IKEv1Attribute DH_GROUP_5 = new IKEv1Attribute(0x80040005);
    public static IKEv1Attribute PKE = new IKEv1Attribute(0x80030004);
    public static IKEv1Attribute LIFETYPE_SEC = new IKEv1Attribute(0x800b0001);
    public static IKEv1Attribute DURATION28800 = new IKEv1Attribute(0x800c7080);
}
