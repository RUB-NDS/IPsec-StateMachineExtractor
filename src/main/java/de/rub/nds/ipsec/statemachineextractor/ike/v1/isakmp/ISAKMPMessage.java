/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp;

import de.rub.nds.ipsec.statemachineextractor.ike.IKEMessage;
import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKECiphersuite;
import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKEHandshakeSessionSecrets;
import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKEParsingException;
import de.rub.nds.ipsec.statemachineextractor.ike.HandshakeLongtermSecrets;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEPayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.IKEv1Ciphersuite;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.IKEv1HandshakeSessionSecrets;
import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import javax.crypto.BadPaddingException;
import javax.crypto.spec.SecretKeySpec;

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
    public void processFromStream(ByteArrayInputStream bais, GenericIKECiphersuite genericCiphersuite, GenericIKEHandshakeSessionSecrets genericSecrets, HandshakeLongtermSecrets ltsecrets) throws GenericIKEParsingException, GeneralSecurityException {
        IKEv1HandshakeSessionSecrets secrets = (IKEv1HandshakeSessionSecrets) genericSecrets;
        IKEv1Ciphersuite ciphersuite = (IKEv1Ciphersuite) genericCiphersuite;
        Map.Entry<Integer, IKEPayloadTypeEnum> entry = super.fillHeaderFromStream(bais);
        int length = entry.getKey();
        IKEPayloadTypeEnum nextPayload = entry.getValue();
        secrets.setResponderCookie(this.getResponderCookie());
        ISAKMPPayload payload;
        if (this.isEncryptedFlag()) {
            bais.reset();
            throw new IsEncryptedException();
        }
        while (nextPayload != IKEPayloadTypeEnum.NONE) {
            switch (nextPayload) {
                case SecurityAssociation:
                    payload = SecurityAssociationPayload.fromStream(bais);
                    SecurityAssociationPayload receivedSAPayload = (SecurityAssociationPayload) payload;
                    ciphersuite.adjust(receivedSAPayload, secrets);
                    break;
                case KeyExchange:
                    switch (ciphersuite.getAuthMethod()) {
                        case RevPKE:
                            SecretKeySpec ke_r = new SecretKeySpec(secrets.getKe_r(), ciphersuite.getCipher().cipherJCEName());
                            SymmetricallyEncryptedISAKMPPayload symmPayload = SymmetricallyEncryptedISAKMPPayload.fromStream(KeyExchangePayload.class, bais, ciphersuite, ke_r, secrets.getRPKEIV());
                            secrets.getHandshakeSA().setPeerKeyExchangeData(((KeyExchangePayload) symmPayload.getUnderlyingPayload()).getKeyExchangeData());
                            payload = symmPayload;
                            break;
                        default:
                            payload = KeyExchangePayload.fromStream(bais);
                            secrets.getHandshakeSA().setPeerKeyExchangeData(((KeyExchangePayload) payload).getKeyExchangeData());
                            break;
                    }
                    secrets.getHandshakeSA().computeDHSecret();
                    break;
                case Identification:
                    bais.mark(0);
                    switch (ciphersuite.getAuthMethod()) {
                        case RevPKE:
                            SecretKeySpec ke_r = new SecretKeySpec(secrets.getKe_r(), ciphersuite.getCipher().cipherJCEName());
                            SymmetricallyEncryptedIdentificationPayloadHuaweiStyle symmPayload = SymmetricallyEncryptedIdentificationPayloadHuaweiStyle.fromStream(bais, ciphersuite, ke_r, secrets.getRPKEIV());
                            secrets.setPeerIdentificationPayloadBody(((IdentificationPayload) symmPayload.getUnderlyingPayload()).getBody());
                            payload = symmPayload;
                            break;
                        case PKE:
                            try {
                                PKCS1EncryptedISAKMPPayload pkcs1Payload = PKCS1EncryptedISAKMPPayload.fromStream(IdentificationPayload.class, bais, ltsecrets.getMyPrivateKey(), ltsecrets.getPeerPublicKeyPKE());
                                secrets.setPeerIdentificationPayloadBody(((IdentificationPayload) pkcs1Payload.getUnderlyingPayload()).getBody());
                                payload = pkcs1Payload;
                                break; // only executed when there's no exception
                            } catch (ISAKMPParsingException ex) {
                                if (!(ex.getCause() instanceof BadPaddingException)) {
                                    throw ex;
                                }
                                // Payload was probably not encrypted, let's use the default case
                                bais.reset();
                            }
                        default:
                            payload = IdentificationPayload.fromStream(bais);
                            secrets.setPeerIdentificationPayloadBody(((IdentificationPayload) payload).getBody());
                            break;
                    }
                    secrets.computeSecretKeys();
                    break;
                case Hash:
                    payload = HashPayload.fromStream(bais);
                    if (Arrays.equals(secrets.getHASH_R(), ((HashPayload) payload).getHashData())) {
                        ((HashPayload) payload).setCheckFailed(false);
                    } else {
                        ((HashPayload) payload).setCheckFailed(true);
                    }
                    break;
                case Nonce:
                    switch (ciphersuite.getAuthMethod()) {
                        case PKE:
                        case RevPKE:
                            bais.mark(0);
                            try {
                                PKCS1EncryptedISAKMPPayload encPayload = PKCS1EncryptedISAKMPPayload.fromStream(NoncePayload.class, bais, ltsecrets.getMyPrivateKey(), ltsecrets.getPeerPublicKeyRPKE());
                                secrets.getHandshakeSA().setResponderNonce(((NoncePayload) encPayload.getUnderlyingPayload()).getNonceData());
                                payload = encPayload;
                                break; // only executed when there's no exception
                            } catch (ISAKMPParsingException ex) {
                                if (!(ex.getCause() instanceof BadPaddingException)) {
                                    throw ex;
                                }
                                // Payload was probably not encrypted, let's use the default case
                                bais.reset();
                            }
                        default:
                            payload = NoncePayload.fromStream(bais);
                            secrets.getHandshakeSA().setResponderNonce(((NoncePayload) payload).getNonceData());
                            break;
                    }
                    secrets.computeSecretKeys();
                    break;
                case VendorID:
                    payload = VendorIDPayload.fromStream(bais);
                    break;
                case Notification:
                    payload = NotificationPayload.fromStream(bais);
                    break;
                default:
                    throw new UnsupportedOperationException("Not supported yet.");
            }
            nextPayload = payload.getNextPayload();
            this.addPayload(payload);
        }
        if (length != this.getLength()) {
            throw new ISAKMPParsingException("Message lengths differ - Computed: " + this.getLength() + " vs. Received: " + length + "!");
        }
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

    public static class IsEncryptedException extends GenericIKEParsingException {

        public IsEncryptedException() {
        }
    }
}
