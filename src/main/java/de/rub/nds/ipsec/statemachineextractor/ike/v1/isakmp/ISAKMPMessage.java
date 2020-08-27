/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp;

import de.rub.nds.ipsec.statemachineextractor.ike.IKEPayloadTypeEnum;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class ISAKMPMessage extends IKEMessage implements ISAKMPSerializable {

    public static final byte VERSION = 0x10;
    protected final List<ISAKMPPayload> payloads = new ArrayList<>();

    public ISAKMPMessage() {
        super(VERSION, 3);
    }

    public final void setEncryptedFlag(boolean value) {
        this.flags.set(0, value);
    }

    public final void setCommitFlag(boolean value) {
        this.flags.set(1, value);
    }

    public final void setAuthenticationOnlyFlag(boolean value) {
        this.flags.set(2, value);
    }

    public final boolean isEncryptedFlag() {
        return this.flags.get(0);
    }

    public final boolean isCommitFlag() {
        return this.flags.get(1);
    }

    public final boolean isAuthenticationOnlyFlag() {
        return this.flags.get(2);
    }

    @Override
    public List<ISAKMPPayload> getPayloads() {
        return Collections.unmodifiableList(payloads);
    }

    public void addPayload(ISAKMPPayload payload) {
        if (!payloads.isEmpty()) {
            payloads.get(payloads.size() - 1).setNextPayload(payload.getType());
        }
        payload.setNextPayload(IKEPayloadTypeEnum.NONE);
        payloads.add(payload);
    }

    public void addPayload(int index, ISAKMPPayload payload) {
        payloads.add(index, payload);
        updateNextPayloadProperty();
    }

    @Override
    protected void toString(StringBuilder name) {
        switch (this.getExchangeType()) {
            case IdentityProtection:
                name.append("MM");
                break;
            case Aggressive:
                name.append("AM");
                break;
            case QuickMode:
                name.append("QM");
                break;
            case Informational:
                name.append("INFO");
                break;
            default:
                throw new UnsupportedOperationException("Not supported yet.");
        }
        if (this.isEncryptedFlag()) {
            name.append("*");
        }
    }
}
