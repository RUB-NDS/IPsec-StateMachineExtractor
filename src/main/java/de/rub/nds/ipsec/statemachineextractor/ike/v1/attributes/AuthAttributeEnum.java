/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.IKEv1Ciphersuite;
import de.rub.nds.ipsec.statemachineextractor.isakmp.BasicAttribute;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public enum AuthAttributeEnum implements IKEv1Attribute, BasicAttribute {

    PSK(0x80030001),
    DSS_Sig(0x80030002),
    RSA_Sig(0x80030003),
    PKE(0x80030004),
    RevPKE(0x80030005);

    protected static final int FORMAT_TYPE = 0x8003;
    private final byte[] bytes;

    private AuthAttributeEnum(int value) {
        this.bytes = DatatypeHelper.intTo4ByteArray(value);
        IKEv1AttributeFactory.register(this, value);
    }

    @Override
    public byte[] getBytes() {
        return bytes.clone();
    }

    @Override
    public void configureCiphersuite(IKEv1Ciphersuite ciphersuite) {
        ciphersuite.setAuthMethod(this);
    }
}
