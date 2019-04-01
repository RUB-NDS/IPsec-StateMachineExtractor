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
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.PayloadTypeEnum;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv1MainModeSecurityAssociationMessage extends ISAKMPMessage {

    public IKEv1MainModeSecurityAssociationMessage() {
        super.setExchangeType(ExchangeTypeEnum.IdentityProtection);
    }
    
    @Override
    protected final void setExchangeType(ExchangeTypeEnum exchangeType) {
        // No action, overwriting exchangeType not allowed
    }
    
    @Override
    public final void addPayload(ISAKMPPayload payload) {
        if (getPayloads().isEmpty() && payload.getType() != PayloadTypeEnum.SecurityAssociation)
            throw new IllegalArgumentException("First payload has to be a Security Association Payload!");
        super.addPayload(payload);
    }
}
