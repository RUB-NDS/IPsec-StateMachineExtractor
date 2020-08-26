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
import de.rub.nds.ipsec.statemachineextractor.ike.DHGroupEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.IKEv1Ciphersuite;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import de.rub.nds.ipsec.statemachineextractor.ike.BasicIKEAttribute;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public enum DHGroupAttributeEnum implements ISAKMPAttribute, BasicIKEAttribute {

    GROUP1(0x80040001, DHGroupEnum.GROUP1_768),
    GROUP2(0x80040002, DHGroupEnum.GROUP2_1024),
    GROUP5(0x80040005, DHGroupEnum.GROUP5_1536),
    GROUP14(0x8004000e, DHGroupEnum.GROUP14_2048),
    GROUP15(0x8004000f, DHGroupEnum.GROUP15_3072),
    GROUP16(0x80040010, DHGroupEnum.GROUP16_4096),
    GROUP17(0x80040011, DHGroupEnum.GROUP17_6144),
    GROUP18(0x80040012, DHGroupEnum.GROUP18_8192),
    GROUP19(0x80040013, DHGroupEnum.GROUP19_256),
    GROUP20(0x80040014, DHGroupEnum.GROUP20_384),
    GROUP21(0x80040015, DHGroupEnum.GROUP21_521);

    protected static final int FORMAT_TYPE = 0x8004;
    private final DHGroupEnum group;
    private final byte[] bytes;

    private DHGroupAttributeEnum(int value, DHGroupEnum group) {
        this.bytes = DatatypeHelper.intTo4ByteArray(value);
        this.group = group;
        IKEv1AttributeFactory.register(this, value);
    }

    public DHGroupEnum getDHGroupParameters() {
        return group;
    }

    @Override
    public byte[] getBytes() {
        return bytes.clone();
    }

    @Override
    public void configureCiphersuite(IKEv1Ciphersuite ciphersuite) {
        ciphersuite.setDhGroup(this);
    }
}
