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
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPMessage;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPParsingException;
import de.rub.nds.ipsec.statemachineextractor.isakmp.SecurityAssociationPayload;
import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEMessageMapper implements SULMapper<IKEInputAlphabetEnum, String, ContextExecutableInput<ISAKMPMessage, IKEv1Handshake>, ISAKMPMessage> {

    static final ISAKMPMessage PARSING_ERROR = new ISAKMPMessage();

    @Override
    public ContextExecutableInput<ISAKMPMessage, IKEv1Handshake> mapInput(IKEInputAlphabetEnum abstractInput) {
        return (IKEv1Handshake handshake) -> {
            ISAKMPMessage msg = new ISAKMPMessage();
            try {
                switch (abstractInput) {
                    case RESET:
                        handshake.reset();
                        return null;
//                    case v1_MM_SA:
//                        msg.setExchangeType(ExchangeTypeEnum.IdentityProtection);
//                        msg.addPayload(SecurityAssociationPayloadFactory.PKE_AES128_SHA1_G5);
//                        break;
//                    case v1_MM_KE:
//                        msg.setExchangeType(ExchangeTypeEnum.IdentityProtection);
//                        msg.addPayload(handshake.prepareKeyExchangePayload());
//                        msg.addPayload(handshake.prepareIdentificationPayload());
//                        msg.addPayload(handshake.prepareNoncePayload());
//                        msg.addPayload(VendorIDPayload.DeadPeerDetection);
//                        break;
//                    case v1_MM_HASH:
//                        msg.setExchangeType(ExchangeTypeEnum.IdentityProtection);
//                        msg.addPayload(handshake.prepareHashPayload());
//                        msg.setEncryptedFlag(true);
//                        break; 
                    case v1_AM_PSK_SA_KE_No_ID:
                        msg.setExchangeType(ExchangeTypeEnum.Aggressive);
                        SecurityAssociationPayload sa = SecurityAssociationPayloadFactory.PSK_AES128_SHA1_G2;
                        msg.addPayload(sa);
                        handshake.adjustCiphersuite(sa);
                        msg.addPayload(handshake.prepareKeyExchangePayload());
                        msg.addPayload(handshake.prepareNoncePayload());
                        msg.addPayload(handshake.prepareIdentificationPayload());
                        break;
                    case v1_AM_HASH:
                        msg.setExchangeType(ExchangeTypeEnum.Aggressive);
                        msg.addPayload(handshake.prepareHashPayload());
                        break;
                    default:
                        throw new UnsupportedOperationException("Not supported yet.");
                }
                return handshake.exchangeMessage(msg);
            } catch (IOException | IKEHandshakeException | GeneralSecurityException ex) {
                throw new SULException(ex);
            } catch (ISAKMPParsingException ex) {
                return PARSING_ERROR;
            }
        };
    }

    @Override
    public String mapOutput(ISAKMPMessage concreteOutput) {
        if (concreteOutput == null) {
            return IKEOutputAlphabet.NO_RESPONSE;
        }
        if (concreteOutput == PARSING_ERROR) {
            return IKEOutputAlphabet.PARSING_ERROR;
        }
        return concreteOutput.toString();
    }
}
