/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.learning;

import de.learnlib.api.exception.SULException;
import de.learnlib.mapper.api.ContextExecutableInput;
import de.learnlib.mapper.api.SULMapper;
import de.rub.nds.ipsec.statemachineextractor.SerializableMessage;
import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKEParsingException;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEHandshakeException;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEHandshake;
import de.rub.nds.ipsec.statemachineextractor.ike.SecurityAssociationPayloadFactory;
import de.rub.nds.ipsec.statemachineextractor.ike.SecurityAssociationSecrets;
import de.rub.nds.ipsec.statemachineextractor.ipsec.ESPMessage;
import de.rub.nds.ipsec.statemachineextractor.ipsec.ESPTransformIDEnum;
import de.rub.nds.ipsec.statemachineextractor.ipsec.IPsecConnection;
import de.rub.nds.ipsec.statemachineextractor.ipsec.attributes.AuthenticationAlgorithmAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ipsec.attributes.KeyLengthAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.ExchangeTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.IDTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ISAKMPMessage;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.IdentificationPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.SecurityAssociationPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.IKEv2Message;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.SecurityAssociationPayloadv2;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.io.IOException;
import java.net.InetAddress;
import java.security.GeneralSecurityException;
import java.util.ArrayDeque;
import java.util.Arrays;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IPsecMessageMapper implements SULMapper<String, String, ContextExecutableInput<SerializableMessage, IPsecConnection>, SerializableMessage> {

    static final ISAKMPMessage PARSING_ERROR_v1 = new ISAKMPMessage();
    static final IKEv2Message PARSING_ERROR_v2 = new IKEv2Message();

    @Override
    public ContextExecutableInput<SerializableMessage, IPsecConnection> mapInput(String abstractInput) {
        return new ContextExecutableInput<SerializableMessage, IPsecConnection>() {
            @Override
            public SerializableMessage execute(IPsecConnection conn) throws SULException {
                try {
                    if (abstractInput.equals("RESET")) {
                        conn.getHandshake().reset();
                        return null;
                    }
                    if (abstractInput.equals("NEW_QM_MSG_ID")) {
                        conn.getHandshake().setMostRecentMessageID(null);
                        adjustQuickModeMessageID(conn.getHandshake(), new ISAKMPMessage());
                        return null;
                    }
                    switch(abstractInput.substring(0, 2)) {
                        case "v1":
                            return executeISAKMP(conn);
                        case "v2":
                            return executeIKEv2(conn);
                        default:
                            return executeESP(conn);
                    }
                } catch (IOException | IKEHandshakeException | GeneralSecurityException ex) {
                    throw new SULException(ex);
                }
            }

            private ISAKMPMessage executeISAKMP(IPsecConnection conn) throws GeneralSecurityException, IKEHandshakeException, UnsupportedOperationException, IOException {
                ISAKMPMessage msg = new ISAKMPMessage();
                SecurityAssociationPayload sa = null;
                IdentificationPayload id;
                try {
                    ArrayDeque<String> tokens = new ArrayDeque<>(Arrays.asList(abstractInput.split("_|\\*")));
                    switch (tokens.pop()) {
                        case "v1":
                            break;
                        default:
                            throw new UnsupportedOperationException("ISAKMP is tightly connected to IKEv1; if you use the ISAKMP method, use a 'v1' message identifier!");
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
                                sa = SecurityAssociationPayloadFactory.V1_P1_PSK_AES128_SHA1_G2;
                                break;
                            case "PKE":
                                sa = SecurityAssociationPayloadFactory.V1_P1_PKE_AES128_SHA1_G5;
                                break;
                            case "RPKE":
                                sa = SecurityAssociationPayloadFactory.V1_P1_RPKE_AES128_SHA1_G5;
                                break;
                            case "SA":
                                switch (msg.getExchangeType()) {
                                    case QuickMode:
                                        sa = SecurityAssociationPayloadFactory.getV1_P2_ESP_TUNNEL_AES128_SHA1();
                                        conn.getHandshake().addInboundSPIAndProtocolToIPsecSecurityAssociation(sa);
                                        break;

                                    default:
                                        conn.getHandshake().adjustCiphersuite(sa);
                                        break;
                                }
                                msg.addPayload(sa);
                                break;
                            case "KE":
                            case "(KE)":
                                msg.addPayload(conn.getHandshake().prepareIKEv1KeyExchangePayload(msg.getMessageId()));
                                break;
                            case "No":
                            case "<No>":
                                msg.addPayload(conn.getHandshake().prepareIKEv1NoncePayload(msg.getMessageId()));
                                break;
                            case "ID":
                            case "<ID>":
                            case "(ID)":
                                msg.addPayload(conn.getHandshake().prepareIKEv1IdentificationPayload());
                                break;
                            case "IDci":
                                id = new IdentificationPayload();
                                id.setIdType(IDTypeEnum.IPV4_ADDR_SUBNET);
                                id.setIdentificationData(DatatypeHelper.hexDumpToByteArray("0a000100ffffff00"));
                                msg.addPayload(id);
                                break;
                            case "IDcr":
                                id = new IdentificationPayload();
                                id.setIdType(IDTypeEnum.IPV4_ADDR_SUBNET);
                                id.setIdentificationData(DatatypeHelper.hexDumpToByteArray("0a000200ffffff00"));
                                msg.addPayload(id);
                                break;
                            case "HASH":
                                msg.addPayload(conn.getHandshake().preparePhase1HashPayload());
                                break;
                            case "DEL":
                                msg.addPayload(conn.getHandshake().prepareIKEv1DeletePayload());
                            // Intentionally no break here
                            case "HASH1":
                                adjustQuickModeMessageID(conn.getHandshake(), msg);
                                requiresHash1PostProcessing = true;
                                break;
                            case "HASH3":
                                adjustQuickModeMessageID(conn.getHandshake(), msg);
                                conn.getHandshake().addIKEv1Phase2Hash3Payload(msg);
                                SecurityAssociationSecrets sas = conn.getHandshake().getMostRecentSecurityAssociationv1();
                                conn.getHandshake().computeIPsecKeyMaterialv1(sas);
                                conn.establishTunnel(sas, ESPTransformIDEnum.AES, KeyLengthAttributeEnum.L128, AuthenticationAlgorithmAttributeEnum.HMAC_SHA);
                                break;

                            default:
                                throw new UnsupportedOperationException("Malformed message identifier");
                        }
                    }
                    if (requiresHash1PostProcessing) {
                        conn.getHandshake().addIKEv1Phase2Hash1Payload(msg);
                    }
                    return (ISAKMPMessage) conn.getHandshake().exchangeMessage(msg);
                } catch (GenericIKEParsingException ex) {
                    return PARSING_ERROR_v1;
                }
            }

            private IKEv2Message executeIKEv2(IPsecConnection conn) throws GeneralSecurityException, IKEHandshakeException, UnsupportedOperationException, IOException {
                IKEv2Message msg = new IKEv2Message();
                msg.setInitiatorFlag(true);
                SecurityAssociationPayloadv2 sa = null;
                try {
                    ArrayDeque<String> tokens = new ArrayDeque<>(Arrays.asList(abstractInput.split("_|\\*")));
                    switch (tokens.pop()) {
                        case "v2":
                            break;
                        default:
                            throw new UnsupportedOperationException("If you use the IKEv2 method, use a 'v2' message identifier!");
                    }
                    switch (tokens.pop()) {
                        case "SAINIT":
                            msg.setExchangeType(ExchangeTypeEnum.IKE_SA_INIT);
                            break;
                        case "AUTH":
                            msg.setExchangeType(ExchangeTypeEnum.IKE_AUTH);
                            break;
                        default:
                            throw new UnsupportedOperationException("Not supported yet.");
                    }
                    String token = tokens.pop();
                    if (!tokens.isEmpty()) {
                        throw new UnsupportedOperationException("Malformed message identifier");
                    }
                    tokens = new ArrayDeque<>(Arrays.asList(token.split("-")));
                    while (!tokens.isEmpty()) {
                        switch (tokens.pop()) {
                            case "PSK":
                                switch (msg.getExchangeType()) {
                                    case IKE_SA_INIT:
                                        sa = SecurityAssociationPayloadFactory.V2_P1_AES_128_CBC_SHA1;
                                        break;
                                    case IKE_AUTH:
                                        sa = SecurityAssociationPayloadFactory.V2_P2_AES_128_CBC_SHA1_ESN;
                                        break;
                                    default:
                                        throw new UnsupportedOperationException("Not supported yet.");
                                }
                                break;
                            case "SA":
                                switch (msg.getExchangeType()) {
                                    case IKE_SA_INIT:
                                        conn.getHandshake().adjustCiphersuite(sa);
                                        break;
                                    case IKE_AUTH:
                                        conn.getHandshake().addInboundSPIAndProtocolToIPsecSecurityAssociation(sa);
                                        break;
                                    default:
                                        throw new UnsupportedOperationException("Not supported yet.");
                                }
                                msg.addPayload(sa);
                                break;
                            case "KE":
                                msg.addPayload(conn.getHandshake().prepareIKEv2KeyExchangePayload(msg.getMessageId()));
                                break;
                            case "No":
                                msg.addPayload(conn.getHandshake().prepareIKEv2NoncePayload(msg.getMessageId()));
                                break;
                            case "IDi":
                                msg.addPayload(conn.getHandshake().prepareIKEv2IdentificationInitiator());
                                break;
                            case "AUTH":
                                msg.addPayload(conn.getHandshake().prepareIKEv2AuthenticationPayload());
                                break;
                            case "TSi":
                                msg.addPayload(conn.getHandshake().prepareIKEv2TrafficSelectorPayloadInitiator());
                                break;
                            case "TSr":
                                msg.addPayload(conn.getHandshake().prepareIKEv2TrafficSelectorPayloadResponder());
                                break;
                            default:
                                throw new UnsupportedOperationException("Malformed message identifier");
                        }
                    }
                    IKEv2Message result = (IKEv2Message) conn.getHandshake().exchangeMessage(msg);
                    if (msg.getExchangeType() == ExchangeTypeEnum.IKE_AUTH) {
                        SecurityAssociationSecrets sas = conn.getHandshake().getIPsecSecurityAssociationv2();
                        conn.getHandshake().computeIPsecKeyMaterialv2(sas);
                        conn.establishTunnel(sas, ESPTransformIDEnum.AES, KeyLengthAttributeEnum.L128, AuthenticationAlgorithmAttributeEnum.HMAC_SHA);
                    }
                    return result;
                } catch (GenericIKEParsingException ex) {
                    return PARSING_ERROR_v2;
                }
            }

            private void adjustQuickModeMessageID(IKEHandshake handshake, ISAKMPMessage msg) {
                if (handshake.getMostRecentMessageID() == null) {
                    msg.setMessageIdRandom();
                    handshake.setMostRecentMessageID(msg.getMessageId());
                }
                msg.setMessageId(handshake.getMostRecentMessageID());
            }

            private ESPMessage executeESP(IPsecConnection conn) throws IOException, GeneralSecurityException {
                if (!abstractInput.equals("ESP_IPv4_TCP_SYN_SSH")) {
                    throw new UnsupportedOperationException("Not supported yet.");
                }
                return conn.exchangeTCPSYN(InetAddress.getByName("10.0.1.1"), InetAddress.getByName("10.0.2.1"), 22);
            }
        };
    }

    @Override
    public String mapOutput(SerializableMessage concreteOutput) {
        if (concreteOutput == null) {
            return IPsecOutputAlphabet.NO_RESPONSE;
        }
        if (concreteOutput == PARSING_ERROR_v1) {
            return IPsecOutputAlphabet.PARSING_ERROR;
        }
        return concreteOutput.toString();
    }
}
