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
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.DHGroupTransformEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.PseudoRandomFunctionTransformEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.EncryptionAlgorithmTransformEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.IntegrityAlgorithmTransformEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.attributes.KeyLengthAttributeEnum;
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
}
