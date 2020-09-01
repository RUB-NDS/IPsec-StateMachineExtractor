/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v2;

import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKECiphersuite;
import de.rub.nds.ipsec.statemachineextractor.ike.DHGroupEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEHandshakeException;
import de.rub.nds.ipsec.statemachineextractor.ike.ProtocolIDEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.DHGroupTransformEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.PseudoRandomFunctionTransformEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.EncryptionAlgorithmTransformEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.IntegrityAlgorithmTransformEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.attributes.KeyLengthAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.ProposalPayloadv2;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.SecurityAssociationPayloadv2;
import java.security.GeneralSecurityException;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv2Ciphersuite extends GenericIKECiphersuite {

    private IntegrityAlgorithmTransformEnum authMethod = IntegrityAlgorithmTransformEnum.SHA1;
    private EncryptionAlgorithmTransformEnum cipher = EncryptionAlgorithmTransformEnum.AES_CBC;
    private DHGroupTransformEnum dhGroup = DHGroupTransformEnum.GROUP2_1024;
    private PseudoRandomFunctionTransformEnum prf = PseudoRandomFunctionTransformEnum.SHA1;
    private KeyLengthAttributeEnum keylength = KeyLengthAttributeEnum.L128;

    public void setAuthMethod(IntegrityAlgorithmTransformEnum authMethod) {
        this.authMethod = authMethod;
    }

    public IntegrityAlgorithmTransformEnum getAuthMethod() {
        return authMethod;
    }

    public EncryptionAlgorithmTransformEnum getCipher() {
        return cipher;
    }

    public void setCipher(EncryptionAlgorithmTransformEnum cipher) {
        this.cipher = cipher;
    }

    @Override
    public DHGroupEnum getDhGroup() {
        return dhGroup.getDHGroupParameters();
    }

    public void setDhGroup(DHGroupTransformEnum dhGroup) {
        this.dhGroup = dhGroup;
    }

    public PseudoRandomFunctionTransformEnum getPrf() {
        return prf;
    }

    public void setPrf(PseudoRandomFunctionTransformEnum prf) {
        this.prf = prf;
    }

    public KeyLengthAttributeEnum getKeylength() {
        return keylength;
    }

    public void setKeylength(KeyLengthAttributeEnum keylength) {
        this.keylength = keylength;
    }

    @Override
    public int getKeySize() {
        return this.keylength.getKeySize();
    }

    @Override
    public int getCipherBlocksize() throws GeneralSecurityException {
        return this.cipher.getBlockSize();
    }

    public void adjust(SecurityAssociationPayloadv2 payload, IKEv2HandshakeSessionSecrets secrets) throws GeneralSecurityException, IKEHandshakeException {
        if (payload.getProposalPayloads().size() != 1) {
            throw new IKEHandshakeException("Wrong number of proposal payloads found. There should only be one.");
        }
        ProposalPayloadv2 pp = payload.getProposalPayloads().get(0);
        if (pp.getProtocolId() != ProtocolIDEnum.ISAKMP_IKE) {
            throw new IKEHandshakeException("Proposal protocol is not ISAKMP.");
        }
        if (pp.getTransformPayloads().isEmpty()) {
            throw new IKEHandshakeException("No transform payloads found. There should be some.");
        }
        pp.getTransformPayloads().forEach((tp) -> {
            tp.configureCiphersuite(this);
        });
        secrets.updateHandshakeSA();
    }
}
