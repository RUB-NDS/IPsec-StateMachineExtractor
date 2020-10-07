/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures;

import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKECiphersuite;
import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKEHandshakeSessionSecrets;
import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKEParsingException;
import de.rub.nds.ipsec.statemachineextractor.ike.HandshakeLongtermSecrets;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEHandshakeException;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEPayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEMessage;
import de.rub.nds.ipsec.statemachineextractor.ike.ProtocolIDEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.SecurityAssociationSecrets;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.IKEv2Ciphersuite;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.IKEv2HandshakeSessionSecrets;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.IKEv2Serializable;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv2Message extends IKEMessage implements IKEv2Serializable {

    public static final byte VERSION = 0x20;
    protected final List<IKEv2Payload> payloads = new ArrayList<>();

    public IKEv2Message() {
        super(VERSION, 6);
    }

    public final void setInitiatorFlag(boolean value) {
        this.flags.set(3, value);
    }

    public final void setVersionFlag(boolean value) {
        this.flags.set(4, value);
    }

    public final void setResponseFlag(boolean value) {
        this.flags.set(5, value);
    }

    public final boolean isInitiatorFlag() {
        return this.flags.get(3);
    }

    public final boolean isVersionFlag() {
        return this.flags.get(4);
    }

    public final boolean isResponseFlag() {
        return this.flags.get(5);
    }

    @Override
    public List<IKEv2Payload> getPayloads() {
        return Collections.unmodifiableList(payloads);
    }

    public void addPayload(IKEv2Payload payload) {
        if (!payloads.isEmpty()) {
            payloads.get(payloads.size() - 1).setNextPayload(payload.getType());
        }
        if (payload.getType() == IKEPayloadTypeEnum.EncryptedAndAuthenticated) {
            if (!payloads.isEmpty()) {
                payload.setNextPayload(payloads.get(0).getType());
            }
            payloads.add(0, payload);
        } else {
            payload.setNextPayload(IKEPayloadTypeEnum.NONE);
            payloads.add(payload);
        }
    }

    public void addPayload(int index, IKEv2Payload payload) {
        payloads.add(index, payload);
        updateNextPayloadProperty();
    }

    @Override
    protected void writeBytesOfPayloads(ByteArrayOutputStream baos) {
        updateNextPayloadProperty();
        for (int i = 0; i < payloads.size(); i++) {
            IKEv2Payload payload = payloads.get(i);
            if (payload.getType() == IKEPayloadTypeEnum.EncryptedAndAuthenticated) {
                payload.writeBytes(baos);
                break;
            }
            payload.writeBytes(baos);
        }
    }

    @Override
    protected void toString(StringBuilder name) {
        switch (this.getExchangeType()) {
            case IKE_SA_INIT:
                name.append("SAINIT");
                break;
            case IKE_AUTH:
                name.append("AUTH");
                break;
            default:
                throw new UnsupportedOperationException("Not supported yet.");
        }
    }

    @Override
    public void processFromStream(ByteArrayInputStream bais, GenericIKECiphersuite genericCiphersuite, GenericIKEHandshakeSessionSecrets genericSecrets, HandshakeLongtermSecrets ltsecrets) throws GenericIKEParsingException, GeneralSecurityException {
        IKEv2HandshakeSessionSecrets secrets = (IKEv2HandshakeSessionSecrets) genericSecrets;
        IKEv2Ciphersuite ciphersuite = (IKEv2Ciphersuite) genericCiphersuite;
        Map.Entry<Integer, IKEPayloadTypeEnum> entry = super.fillHeaderFromStream(bais);
        int length = entry.getKey();
        IKEPayloadTypeEnum nextPayload = entry.getValue();
        secrets.setResponderCookie(this.getResponderCookie());
        if (nextPayload == IKEPayloadTypeEnum.EncryptedAndAuthenticated) {
            bais.reset();
            throw new IsEncryptedException();
        }
        IKEv2Payload payload;
        while (nextPayload != IKEPayloadTypeEnum.NONE) {
            switch (nextPayload) {
                case SecurityAssociationv2:
                    payload = SecurityAssociationPayloadv2.fromStream(bais);
                    break;
                case KeyExchangev2:
                    payload = KeyExchangePayloadv2.fromStream(bais);
                    break;
                case Noncev2:
                    payload = NoncePayloadv2.fromStream(bais);
                    break;
                case Notify:
                    payload = NotificationPayloadv2.fromStream(bais);
                    break;
                default:
                    throw new UnsupportedOperationException("Not supported yet.");
            }
            nextPayload = payload.getNextPayload();
            this.addPayload(payload);
        }
        adjustSA(secrets.getSA(this.getMessageId()), ciphersuite);
        secrets.computeSecretKeys();
    }

    protected void adjustSA(SecurityAssociationSecrets sas, IKEv2Ciphersuite ciphersuite) throws GeneralSecurityException, IKEHandshakeException {
        for (IKEv2Payload payload : payloads) {
            switch (payload.getType()) {
                case SecurityAssociationv2:
                    SecurityAssociationPayloadv2 receivedSAPayload = (SecurityAssociationPayloadv2) payload;
                    if (receivedSAPayload.getProposalPayloads().size() != 1) {
                        throw new IKEHandshakeException("Wrong number of proposal payloads found. There should only be one.");
                    }
                    ProposalPayloadv2 pp = receivedSAPayload.getProposalPayloads().get(0);
                    if (pp.getProtocolId() != ProtocolIDEnum.ISAKMP_IKE) {
                        sas.setOutboundSpi(pp.getSPI());
                    }
                    break;
                case KeyExchangev2:
                    sas.setPeerKeyExchangeData(((KeyExchangePayloadv2) payload).getKeyExchangeData());
                    sas.computeDHSecret();
                    break;
                case Noncev2:
                    sas.setResponderNonce(((NoncePayloadv2) payload).getNonceData());
                    break;
            }
        }
    }

    public static class IsEncryptedException extends GenericIKEParsingException {

        public IsEncryptedException() {
        }
    }
}
