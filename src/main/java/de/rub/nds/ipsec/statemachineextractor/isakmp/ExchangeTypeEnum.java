/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public enum ExchangeTypeEnum {

    NONE((byte) 0),
    Base((byte) 1),
    IdentityProtection((byte) 2),
    AuthenticationOnly((byte) 3),
    Aggressive((byte) 4),
    Informational((byte) 5);

    private final byte value;

    private ExchangeTypeEnum(byte value) {
        this.value = value;
    }

    public byte getValue() {
        return value;
    }

}
