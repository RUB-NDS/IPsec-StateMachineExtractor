/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.AuthAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.CipherAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.DHGroupAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.LifeDurationAttribute;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.HashAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.KeyLengthAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.LifeTypeAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKECiphersuite;
import de.rub.nds.ipsec.statemachineextractor.ike.DHGroupEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEHandshakeException;
import de.rub.nds.ipsec.statemachineextractor.ike.ProtocolIDEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ISAKMPAttribute;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ProposalPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.SecurityAssociationPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.TransformPayload;
import de.rub.nds.ipsec.statemachineextractor.ipsec.ProtocolTransformIDEnum;
import java.security.GeneralSecurityException;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv1Ciphersuite extends GenericIKECiphersuite {

    private AuthAttributeEnum authMethod = AuthAttributeEnum.PSK;
    private CipherAttributeEnum cipher = CipherAttributeEnum.DES_CBC;
    private DHGroupAttributeEnum dhGroup = DHGroupAttributeEnum.GROUP1;
    private LifeDurationAttribute duration = LifeDurationAttribute.get(28800);
    private HashAttributeEnum hash = HashAttributeEnum.MD5;
    private KeyLengthAttributeEnum keylength = KeyLengthAttributeEnum.L128;
    private LifeTypeAttributeEnum lifetype = LifeTypeAttributeEnum.SECONDS;

    public AuthAttributeEnum getAuthMethod() {
        return authMethod;
    }

    public void setAuthMethod(AuthAttributeEnum authMethod) {
        this.authMethod = authMethod;
    }

    public CipherAttributeEnum getCipher() {
        return cipher;
    }

    public void setCipher(CipherAttributeEnum cipher) {
        this.cipher = cipher;
    }

    @Override
    public DHGroupEnum getDhGroup() {
        return dhGroup.getDHGroupParameters();
    }

    public void setDhGroup(DHGroupAttributeEnum dhGroup) {
        this.dhGroup = dhGroup;
    }

    public LifeDurationAttribute getDuration() {
        return duration;
    }

    public void setDuration(LifeDurationAttribute duration) {
        this.duration = duration;
    }

    public HashAttributeEnum getHash() {
        return hash;
    }

    public void setHash(HashAttributeEnum hash) {
        this.hash = hash;
    }

    public KeyLengthAttributeEnum getKeylength() {
        return keylength;
    }

    public void setKeylength(KeyLengthAttributeEnum keylength) {
        this.keylength = keylength;
    }

    @Override
    public int getKeySize() {
        if (this.cipher == null) {
            throw new IllegalStateException("No cipher set!");
        }
        int keySize = this.cipher.getKeySize();
        if (keySize != 0) {
            return keySize;
        }
        if (this.keylength == null) {
            throw new IllegalStateException("Cipher has variable key size and no KeyLengthAttribute set!");
        }
        return this.keylength.getKeySize();
    }

    public LifeTypeAttributeEnum getLifetype() {
        return lifetype;
    }

    public void setLifetype(LifeTypeAttributeEnum lifetype) {
        this.lifetype = lifetype;
    }

    @Override
    public int getCipherBlocksize() throws GeneralSecurityException {
        return this.cipher.getBlockSize();
    }

    public void adjust(SecurityAssociationPayload payload, IKEv1HandshakeSessionSecrets secrets) throws GeneralSecurityException, IKEHandshakeException {
        if (payload.getProposalPayloads().size() != 1) {
            throw new IKEHandshakeException("Wrong number of proposal payloads found. There should only be one.");
        }
        ProposalPayload pp = payload.getProposalPayloads().get(0);
        if (pp.getProtocolId() != ProtocolIDEnum.ISAKMP_IKE) {
            throw new IKEHandshakeException("Proposal protocol is not ISAKMP.");
        }
        if (pp.getTransformPayloads().size() != 1) {
            throw new IKEHandshakeException("Wrong number of transform payloads found. There should only be one.");
        }
        TransformPayload tp = pp.getTransformPayloads().get(0);
        if (tp.getTransformId().getValue() != ProtocolTransformIDEnum.ISAKMP_KEY_IKE.getValue()) {
            throw new IKEHandshakeException("Transform ID is not the the hybrid ISAKMP/Oakley Diffie-Hellman key exchange (IKE).");
        }
        tp.getAttributes().forEach((attr) -> {
            ISAKMPAttribute iattr = (ISAKMPAttribute) attr;
            iattr.configureCiphersuite(this);
        });
        secrets.updateHandshakeSA();
    }
}
