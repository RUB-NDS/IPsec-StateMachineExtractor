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
import java.util.ArrayDeque;
import java.util.Arrays;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEMessageMapper implements SULMapper<String, String, ContextExecutableInput<ISAKMPMessage, IKEv1Handshake>, ISAKMPMessage> {

    static final ISAKMPMessage PARSING_ERROR = new ISAKMPMessage();

    @Override
    public ContextExecutableInput<ISAKMPMessage, IKEv1Handshake> mapInput(String abstractInput) {
        return new ContextExecutableInput<ISAKMPMessage, IKEv1Handshake>() {
            @Override
            public ISAKMPMessage execute(IKEv1Handshake handshake) throws SULException {
                ISAKMPMessage msg = new ISAKMPMessage();
                SecurityAssociationPayload sa = null;
                try {
                    if (abstractInput.equals("RESET")) {
                        handshake.reset();
                        return null;
                    }
                    ArrayDeque<String> tokens = new ArrayDeque<>(Arrays.asList(abstractInput.split("_|\\*")));
                    switch (tokens.pop()) {
                        case "v1":
                            msg.setVersion((byte) 0x10);
                            break;
                        case "v2":
                            msg.setVersion((byte) 0x20);
                            break;
                        default:
                            throw new UnsupportedOperationException("Not supported yet.");
                    }
                    switch (tokens.pop()) {
                        case "MM":
                            msg.setExchangeType(ExchangeTypeEnum.IdentityProtection);
                            break;
                        case "AM":
                            msg.setExchangeType(ExchangeTypeEnum.Aggressive);
                            break;
                        case "QM":
                            msg.setExchangeType(ExchangeTypeEnum.QuickMode);
                            sa = SecurityAssociationPayloadFactory.PSK_AES128_SHA1_G2;
                            break;
                        case "INFO":
                            msg.setExchangeType(ExchangeTypeEnum.Informational);
                            break;
                        default:
                            throw new UnsupportedOperationException("Not supported yet.");
                    }
                    String token = tokens.pop();
                    if (token.equals("")) {
                        // There was a star-character, so enable encryption
                        msg.setEncryptedFlag(true);
                        token = tokens.pop();
                    }
                    if (!tokens.isEmpty()) {
                        throw new UnsupportedOperationException("Malformed message identifier");
                    }
                    tokens = new ArrayDeque<>(Arrays.asList(token.split("-")));
                    while (!tokens.isEmpty()) {
                        switch (tokens.pop()) {
                            case "PSK":
                                sa = SecurityAssociationPayloadFactory.PSK_AES128_SHA1_G2;
                                break;
                            case "SA":
                                msg.addPayload(sa);
                                handshake.adjustCiphersuite(sa);
                                break;
                            case "KE":
                                msg.addPayload(handshake.prepareKeyExchangePayload());
                                break;
                            case "No":
                                msg.addPayload(handshake.prepareNoncePayload());
                                break;
                            case "ID":
                                msg.addPayload(handshake.prepareIdentificationPayload());
                                break;
                            case "HASH":
                                msg.addPayload(handshake.preparePhase1HashPayload());
                                break;
                            case "HASH1":
                                msg.setMessageIdRandom();
                                msg.addPayload(handshake.preparePhase2Hash1Payload());
                                break;
                        }
                    }
                    return handshake.exchangeMessage(msg);
                } catch (IOException | IKEHandshakeException | GeneralSecurityException ex) {
                    throw new SULException(ex);
                } catch (ISAKMPParsingException ex) {
                    return PARSING_ERROR;
                }
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
