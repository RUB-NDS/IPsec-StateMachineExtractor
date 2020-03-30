/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v2.attributes;

import de.rub.nds.ipsec.statemachineextractor.ike.IKEDHGroupEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.IKEv2Ciphersuite;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPSerializable;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public enum DHGroupAttributeEnum implements IKEv2Attribute, ISAKMPSerializable {

    GROUP2(0x80040002, IKEDHGroupEnum.GROUP2_1024);
	
    private final IKEDHGroupEnum group;
    private final byte[] bytes;

    private DHGroupAttributeEnum(int value, IKEDHGroupEnum group) {
        this.bytes = DatatypeHelper.intTo4ByteArray(value);
        this.group = group;
        IKEv2AttributeFactory.register(this, value);
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
