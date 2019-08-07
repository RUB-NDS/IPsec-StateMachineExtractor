/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.IKEv1Ciphersuite;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPParsingException;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPSerializable;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class DurationAttribute implements IKEv1Attribute, ISAKMPSerializable {

    static DurationAttribute generate(int duration) {
        check(duration);
        return new DurationAttribute((0x800c << 16) + duration);
    }
    
    private final byte[] bytes;

    private DurationAttribute(int value) {
       this.bytes = DatatypeHelper.intTo4ByteArray(value);
       IKEv1AttributeFactory.register(this, value);
    }

    @Override
    public byte[] getBytes() {
        return bytes.clone();
    }
    
    public static DurationAttribute get(int duration) {
        check(duration);
        try {
            return (DurationAttribute) IKEv1AttributeFactory.fromInt((0x800c << 16) + duration);
        } catch (ISAKMPParsingException ex) {
            throw new RuntimeException("This should not be possible", ex);
        }
    }
    
    private static void check(int duration) {
        if (duration > 0xFFFF) {
            throw new IllegalArgumentException("Duration too large.");
        }
    }    

    @Override
    public void configureCiphersuite(IKEv1Ciphersuite ciphersuite) {
        ciphersuite.setDuration(this);
    }
}