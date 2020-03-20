/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.IKEv1Ciphersuite;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPSerializable;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.security.GeneralSecurityException;
import javax.crypto.Cipher;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public enum CipherAttributeEnum implements IKEv1Attribute, ISAKMPSerializable {

    DES_CBC(0x80010001, 8),
    IDEA_CBC(0x80010002, 16),
    Blowfish_CBC(0x80010003, 0),
    RC5_R16_B64_CBC(0x80010004, 0),
    TRIPPLEDES_CBC(0x80010005, 24),
    CAST_CBC(0x80010006, 0),
    AES_CBC(0x80010007, 0);

    protected static final int FORMAT_TYPE = 0x8001;
    private final int keySize;
    private final byte[] bytes;
    private int blockSize;

    private CipherAttributeEnum(int value, int keySize) {
        this.bytes = DatatypeHelper.intTo4ByteArray(value);
        this.keySize = keySize;
        IKEv1AttributeFactory.register(this, value);
    }

    public boolean isFixedKeySize() {
        return keySize != 0;
    }

    @Override
    public byte[] getBytes() {
        return bytes.clone();
    }

    @Override
    public void configureCiphersuite(IKEv1Ciphersuite ciphersuite) {
        ciphersuite.setCipher(this);
    }

    public String cipherJCEName() {
        switch (this) {
            case DES_CBC:
                return "DES";
            case IDEA_CBC:
                return "IDEA";
            case Blowfish_CBC:
                return "Blowfish";
            case RC5_R16_B64_CBC:
                return "RC5-64";
            case TRIPPLEDES_CBC:
                return "DESede";
            case CAST_CBC:
                return "CAST5";
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
