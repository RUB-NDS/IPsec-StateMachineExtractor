/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes;

import de.rub.nds.ipsec.statemachineextractor.ike.IKEDHGroupEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.IKEv1Ciphersuite;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPSerializable;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public enum DHGroupAttributeEnum implements IKEv1Attribute, ISAKMPSerializable {

    GROUP1(0x80040001, IKEDHGroupEnum.GROUP1_768),
    GROUP2(0x80040002, IKEDHGroupEnum.GROUP2_1024),
    GROUP5(0x80040005, IKEDHGroupEnum.GROUP5_1536),
    GROUP14(0x8004000e, IKEDHGroupEnum.GROUP14_2048),
    GROUP15(0x8004000f, IKEDHGroupEnum.GROUP15_3072),
    GROUP16(0x80040010, IKEDHGroupEnum.GROUP16_4096),
    GROUP17(0x80040011, IKEDHGroupEnum.GROUP17_6144),
    GROUP18(0x80040012, IKEDHGroupEnum.GROUP18_8192),
    GROUP19(0x80040013, IKEDHGroupEnum.GROUP19_256),
    GROUP20(0x80040014, IKEDHGroupEnum.GROUP20_384),
    GROUP21(0x80040015, IKEDHGroupEnum.GROUP21_521);

    private final IKEDHGroupEnum group;
    private final byte[] bytes;

    private DHGroupAttributeEnum(int value, IKEDHGroupEnum group) {
        this.bytes = DatatypeHelper.intTo4ByteArray(value);
        this.group = group;
        IKEv1AttributeFactory.register(this, value);
    }

    public IKEDHGroupEnum getDHGroupParameters() {
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
