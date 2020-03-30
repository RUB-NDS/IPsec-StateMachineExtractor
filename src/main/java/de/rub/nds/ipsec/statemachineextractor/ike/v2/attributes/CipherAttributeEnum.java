/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKE/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v2.attributes;

import de.rub.nds.ipsec.statemachineextractor.ike.v2.IKEv2Ciphersuite;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPSerializable;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.security.GeneralSecurityException;
import javax.crypto.Cipher;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public enum CipherAttributeEnum implements IKEv2Attribute, ISAKMPSerializable {

    AES_CBC(0x0100000c, 0);

    private final int keySize;
    private final byte[] bytes;
    private int blockSize;

    private CipherAttributeEnum(int value, int keySize) {
        this.bytes = DatatypeHelper.intTo4ByteArray(value);
        this.keySize = keySize;
        IKEv2AttributeFactory.register(this, value);
    }

    public boolean isFixedKeySize() {
        return keySize != 0;
    }

    @Override
    public byte[] getBytes() {
        return bytes.clone();
    }

    @Override
    public void configureCiphersuite(IKEv2Ciphersuite ciphersuite) {
        ciphersuite.setCipher(this);
    }

    public String cipherJCEName() {
        switch (this) {
            case AES_CBC:
                return "AES";
        }
        throw new UnsupportedOperationException("Impossible unless you extend the enum!");
    }

    public String modeOfOperationJCEName() {
        return "CBC"; // it's as simple as that ¯\_(ツ)_/¯
    }

    public int getBlockSize() throws GeneralSecurityException {
        if (blockSize == 0) {
            blockSize = Cipher.getInstance(cipherJCEName()).getBlockSize();
        }
        return blockSize;
    }

    public int getKeySize() {
        return keySize;
    }
}
