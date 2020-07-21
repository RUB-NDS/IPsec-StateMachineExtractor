/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v2;

import de.rub.nds.ipsec.statemachineextractor.ipsec.ProtocolTransformIDEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.v2.transforms.TransformDHEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.v2.transforms.TransformPRFEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.v2.transforms.TransformENCREnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.v2.transforms.TransformINTEGEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.attributes.KeyLengthAttributeEnum;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv2Ciphersuite {

    private TransformINTEGEnum authMethod = TransformINTEGEnum.SHA1;
    private TransformENCREnum cipher = TransformENCREnum.AES_CBC;
    private TransformDHEnum dhGroup = TransformDHEnum.GROUP2;
    private TransformPRFEnum prf = TransformPRFEnum.SHA1;
    private KeyLengthAttributeEnum keylength = KeyLengthAttributeEnum.L128;
    private int nonceLen = 32;

    public void setAuthMethod(TransformINTEGEnum authMethod) {
        this.authMethod = authMethod;
    }
    
    public TransformINTEGEnum getAuthMethod() {
    	return authMethod;
    }

    public TransformENCREnum getCipher() {
        return cipher;
    }

    public void setCipher(TransformENCREnum cipher) {
        this.cipher = cipher;
    }

    public TransformDHEnum getDhGroup() {
        return dhGroup;
    }

    public void setDhGroup(TransformDHEnum dhGroup) {
        this.dhGroup = dhGroup;
    }

    public TransformPRFEnum getPrf() {
        return prf;
    }

    public void setPrf(TransformPRFEnum prf) {
        this.prf = prf;
    }

    public KeyLengthAttributeEnum getKeylength() {
        return keylength;
    }

    public void setKeylength(KeyLengthAttributeEnum keylength) {
        this.keylength = keylength;
    }

    public int getKeySize() {
        return this.keylength.getKeySize();
    }
    /**
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
    **/

    public int getNonceLen() {
        return nonceLen;
    }

    public void setNonceLen(int nonceLen) {
        this.nonceLen = nonceLen;
    }
}
