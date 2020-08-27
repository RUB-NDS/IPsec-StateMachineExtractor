/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures;

import de.rub.nds.ipsec.statemachineextractor.ike.IKEPayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.IKEMessage;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.IKEv2Serializable;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

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
                name.append("INIT");
                break;
            case IKE_AUTH:
                name.append("AUTH");
                break;
            default:
                throw new UnsupportedOperationException("Not supported yet.");
        }
    }
}
