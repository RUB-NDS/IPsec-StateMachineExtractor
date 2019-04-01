/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ikev1;

import de.rub.nds.ipsec.statemachineextractor.isakmp.ExchangeTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPMessage;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public abstract class IKEv1MainModeMessage extends ISAKMPMessage {

    public IKEv1MainModeMessage() {
        super.setExchangeType(ExchangeTypeEnum.IdentityProtection);
    }

    @Override
    protected final void setExchangeType(ExchangeTypeEnum exchangeType) {
        // No action, overwriting exchangeType not allowed
    }

}
