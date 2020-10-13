/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures;

import java.security.GeneralSecurityException;
import javax.crypto.SecretKey;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class EncryptedIKEv2MessageMock extends EncryptedIKEv2Message {

    public EncryptedIKEv2MessageMock(SecretKey ENCRsecretKey, EncryptionAlgorithmTransformEnum mode, byte[] IV, SecretKey INTEGsecretKey, IntegrityAlgorithmTransformEnum auth) throws GeneralSecurityException {
        super(ENCRsecretKey, mode, IV, INTEGsecretKey, auth);
    }

    public EncryptedPayload getENCRPayload() {
        return ENCRPayload;
    }

    public void setENCRPayload(EncryptedPayload ENCRPayload) {
        this.ENCRPayload = ENCRPayload;
    }

    public static EncryptedIKEv2MessageMock fromPlainMessage(IKEv2Message msg, SecretKey ENCRsecretKey, EncryptionAlgorithmTransformEnum mode, byte[] IV, SecretKey INTEGsecretKey, IntegrityAlgorithmTransformEnum auth) throws GeneralSecurityException {
        EncryptedIKEv2MessageMock enc = new EncryptedIKEv2MessageMock(ENCRsecretKey, mode, IV, INTEGsecretKey, auth);
        enc.setInitiatorCookie(msg.getInitiatorCookie());
        enc.setResponderCookie(msg.getResponderCookie());
        enc.setVersion(msg.getVersion());
        enc.setMessageId(msg.getMessageId());
        enc.setExchangeType(msg.getExchangeType());
        enc.setInitiatorFlag(msg.isInitiatorFlag());
        enc.setVersionFlag(msg.isVersionFlag());
        enc.setResponseFlag(msg.isResponseFlag());
        msg.getPayloads().forEach((p) -> {
            enc.addPayload(p);
        });
        return enc;
    }
}
