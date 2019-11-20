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
import de.rub.nds.ipsec.statemachineextractor.isakmp.IDTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPMessage;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPParsingException;
import de.rub.nds.ipsec.statemachineextractor.isakmp.IdentificationPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.SecurityAssociationPayload;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
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
                IdentificationPayload id = null;
                try {
                    if (abstractInput.equals("RESET")) {
                        handshake.reset();
                        return null;
                    }
                    if (abstractInput.equals("NEW_QM_MSG_ID")) {
                        handshake.setMostRecentMessageID(null);
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
                    boolean requiresHash1PostProcessing = false;
                    tokens = new ArrayDeque<>(Arrays.asList(token.split("-")));
                    while (!tokens.isEmpty()) {
                        switch (tokens.pop()) {
                            case "PSK":
                                sa = SecurityAssociationPayloadFactory.P1_PSK_AES128_SHA1_G2;
                                break;
                            case "PKE":
                                sa = SecurityAssociationPayloadFactory.P1_PKE_AES128_SHA1_G5;
                                break;
                            case "SA":
                                switch (msg.getExchangeType()) {
                                    case QuickMode:
                                        sa = SecurityAssociationPayloadFactory.P2_ESP_TUNNEL_AES128_SHA1;
                                        break;
                                    default:
                                        handshake.adjustCiphersuite(sa);
                                        break;
                                }
                                msg.addPayload(sa);
                                break;
                            case "KE":
                                msg.addPayload(handshake.prepareKeyExchangePayload(msg.getMessageId()));
                                break;
                            case "No":
                            case "<No>":
                                msg.addPayload(handshake.prepareNoncePayload(msg.getMessageId()));
                                break;
                            case "ID":
                            case "<ID>":
                                msg.addPayload(handshake.prepareIdentificationPayload());
                                break;
                            case "IDci":
                                id = new IdentificationPayload();
                                id.setIdType(IDTypeEnum.ID_IPV4_ADDR_SUBNET);
                                id.setIdentificationData(DatatypeHelper.hexDumpToByteArray("0a000100ffffff00"));
                                msg.addPayload(id);
                                break;
                            case "IDcr":
                                id = new IdentificationPayload();
                                id.setIdType(IDTypeEnum.ID_IPV4_ADDR_SUBNET);
                                id.setIdentificationData(DatatypeHelper.hexDumpToByteArray("0a000200ffffff00"));
                                msg.addPayload(id);
                                break;
                            case "HASH":
                                msg.addPayload(handshake.preparePhase1HashPayload());
                                break;
                            case "HASH1":
                                adjustQuickModeMessageID(handshake, msg);
                                requiresHash1PostProcessing = true;
                                break;
                            case "HASH3":
                                adjustQuickModeMessageID(handshake, msg);
                                handshake.addPhase2Hash3Payload(msg);
                                break;
                            default:
                                throw new UnsupportedOperationException("Malformed message identifier");
                        }
                    }
                    if (requiresHash1PostProcessing) {
                        handshake.addPhase2Hash1Payload(msg);
                    }
                    return handshake.exchangeMessage(msg);
                } catch (IOException | IKEHandshakeException | GeneralSecurityException ex) {
                    throw new SULException(ex);
                } catch (ISAKMPParsingException ex) {
                    return PARSING_ERROR;
                }
            }

            private void adjustQuickModeMessageID(IKEv1Handshake handshake, ISAKMPMessage msg) {
                if (handshake.getMostRecentMessageID() == null) {
                    msg.setMessageIdRandom();
                    handshake.setMostRecentMessageID(msg.getMessageId());
                }
                msg.setMessageId(handshake.getMostRecentMessageID());
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
