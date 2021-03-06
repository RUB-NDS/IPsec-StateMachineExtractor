/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ISAKMPAttribute;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.IKEv1Ciphersuite;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ISAKMPParsingException;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.io.ByteArrayInputStream;
import de.rub.nds.ipsec.statemachineextractor.ike.BasicIKEAttribute;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class LifeDurationAttribute implements ISAKMPAttribute, BasicIKEAttribute {

    static LifeDurationAttribute generate(int duration) {
        check(duration);
        return new LifeDurationAttribute((FORMAT_TYPE << 16) + duration);
    }

    protected static final int FORMAT_TYPE = 0x800c;
    private final byte[] bytes;

    private LifeDurationAttribute(int value) {
        this.bytes = DatatypeHelper.intTo4ByteArray(value);
        IKEv1AttributeFactory.register(this, value);
    }

    @Override
    public byte[] getBytes() {
        return bytes.clone();
    }

    public static LifeDurationAttribute get(int duration) {
        check(duration);
        byte[] bytes = DatatypeHelper.intTo4ByteArray((FORMAT_TYPE << 16) + duration);
        try {
            return (LifeDurationAttribute) IKEv1AttributeFactory.fromStream(new ByteArrayInputStream(bytes));
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
