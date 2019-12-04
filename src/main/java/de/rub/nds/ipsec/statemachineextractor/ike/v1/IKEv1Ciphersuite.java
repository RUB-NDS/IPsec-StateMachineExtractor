/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
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

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv1Ciphersuite {

    private AuthAttributeEnum authMethod = AuthAttributeEnum.PSK;
    private CipherAttributeEnum cipher = CipherAttributeEnum.DES_CBC;
    private DHGroupAttributeEnum dhGroup = DHGroupAttributeEnum.GROUP1;
    private LifeDurationAttribute duration = LifeDurationAttribute.get(28800);
    private HashAttributeEnum hash = HashAttributeEnum.MD5;
    private KeyLengthAttributeEnum keylength = KeyLengthAttributeEnum.L128;
    private LifeTypeAttributeEnum lifetype = LifeTypeAttributeEnum.SECONDS;
    private int nonceLen = 16; // RFC2409: 8 - 256 bytes (inclusive); Huawei works with 16 bytes

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

    public DHGroupAttributeEnum getDhGroup() {
        return dhGroup;
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

    public int getNonceLen() {
        return nonceLen;
    }

    public void setNonceLen(int nonceLen) {
        this.nonceLen = nonceLen;
    }
}
