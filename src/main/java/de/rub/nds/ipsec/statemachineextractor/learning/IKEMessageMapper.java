/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.learning;

import de.learnlib.api.exception.SULException;
import de.learnlib.mapper.api.ContextExecutableInput;
import de.learnlib.mapper.api.SULMapper;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEHandshakeException;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.IKEv1Handshake;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.SecurityAssociationPayloadFactory;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ExchangeTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.HashPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPMessage;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPParsingException;
import de.rub.nds.ipsec.statemachineextractor.isakmp.IdentificationPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.KeyExchangePayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.NoncePayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.VendorIDPayload;
import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEMessageMapper implements SULMapper<IKEAlphabetEnum, IKEAlphabetEnum, ContextExecutableInput<ISAKMPMessage, IKEv1Handshake>, ISAKMPMessage> {

    @Override
    public ContextExecutableInput<ISAKMPMessage, IKEv1Handshake> mapInput(IKEAlphabetEnum abstractInput) {
        return (IKEv1Handshake handshake) -> {
            ISAKMPMessage msg = new ISAKMPMessage();
            try {
                switch (abstractInput) {
                    case IKEv1_MM_SA_PKE:
                        msg.setExchangeType(ExchangeTypeEnum.IdentityProtection);
                        msg.addPayload(SecurityAssociationPayloadFactory.PKE_AES128_SHA1_G5);
                        break;
                    case IKEv1_MM_KEX_PKE:
                        msg.setExchangeType(ExchangeTypeEnum.IdentityProtection);
                        KeyExchangePayload keyExchangePayload = handshake.prepareKeyExchangePayload();
                        msg.addPayload(keyExchangePayload);
                        IdentificationPayload identificationPayload = handshake.prepareIdentificationPayload();
                        msg.addPayload(identificationPayload);
                        NoncePayload noncePayload = handshake.prepareNoncePayload();
                        msg.addPayload(noncePayload);
                        msg.addPayload(VendorIDPayload.DeadPeerDetection);
                        break;
                    case IKEv1_MM_HASH:
                        msg.setExchangeType(ExchangeTypeEnum.IdentityProtection);
                        HashPayload hashPayload = handshake.prepareHashPayload();
                        msg.addPayload(hashPayload);
                        break;
                    default:
                        throw new UnsupportedOperationException("Not supported yet.");
                }
                return handshake.exchangeMessage(msg);
            } catch (IOException | ISAKMPParsingException | IKEHandshakeException | GeneralSecurityException ex) {
                throw new SULException(ex);
            }
        };
    }

    @Override
    public IKEAlphabetEnum mapOutput(ISAKMPMessage concreteOutput) {
        if(concreteOutput == null) {
            return IKEAlphabetEnum.NO_RESPONSE;
        }
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
}
