/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1;

import de.rub.nds.ipsec.statemachineextractor.ike.IKEDHGroupEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPSerializable;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv1Attribute implements ISAKMPSerializable {

    private final byte[] bytes;

    protected IKEv1Attribute(int bytes) {
        //TODO: Implement dynamically sized attributes
        this.bytes = DatatypeHelper.intTo4ByteArray(bytes);
    }

    @Override
    public int getLength() {
        //TODO: Implement dynamically sized attributes
        return 4;
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        //TODO: Implement dynamically sized attributes
        baos.write(bytes, 0, 4);
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof IKEv1Attribute)) {
            return false;
        }
        IKEv1Attribute o = (IKEv1Attribute) obj;
        return Arrays.equals(this.bytes, o.bytes);
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 97 * hash + Arrays.hashCode(this.bytes);
        return hash;
    }

    // Reverse-lookup map
    private static final Map<Integer, FixedValueIKEv1Attribute> lookup = new HashMap<>();

    public static FixedValueIKEv1Attribute fromInt(int value) {
        return lookup.get(value);
    }

    public interface FixedValueIKEv1Attribute {

        public IKEv1Attribute getAttribute();
    }

    public enum Auth implements FixedValueIKEv1Attribute {
        PSK(0x80030001),
        DSS_Sig(0x80030002),
        RSA_Sig(0x80030003),
        PKE(0x80030004),
        RevPKE(0x80030005);

        private final IKEv1Attribute attr;

        private Auth(int value) {
            this.attr = new IKEv1Attribute(value);
            lookup.put(value, this);
        }

        @Override
        public IKEv1Attribute getAttribute() {
            return attr;
        }
    }

    public enum DH implements FixedValueIKEv1Attribute {
        GROUP1(0x80040001, IKEDHGroupEnum.GROUP1_768),
        GROUP2(0x80040002, IKEDHGroupEnum.GROUP2_1024),
        GROUP5(0x80040005, IKEDHGroupEnum.GROUP5_1536),
        GROUP14(0x8004000e, IKEDHGroupEnum.GROUP14_2048),
        GROUP15(0x8004000f, IKEDHGroupEnum.GROUP15_3072),
        GROUP16(0x80040010, IKEDHGroupEnum.GROUP16_4096),
        GROUP17(0x80040011, IKEDHGroupEnum.GROUP17_6144),
        GROUP18(0x80040012, IKEDHGroupEnum.GROUP18_8192),
        GROUP19(0x80040013, IKEDHGroupEnum.GROUP19_256),
        GROUP20(0x80040014, IKEDHGroupEnum.GROUP20_384),
        GROUP21(0x80040015, IKEDHGroupEnum.GROUP21_521);

        private final IKEv1Attribute attr;
        private final IKEDHGroupEnum group;

        private DH(int value, IKEDHGroupEnum group) {
            this.attr = new IKEv1Attribute(value);
            this.group = group;
            lookup.put(value, this);
        }

        @Override
        public IKEv1Attribute getAttribute() {
            return attr;
        }

        public IKEDHGroupEnum getDHGroup() {
            return group;
        }
    }

    public enum LifeType implements FixedValueIKEv1Attribute {
        SECONDS(0x800b0001),
        KILOBYTES(0x800b0002);

        private final IKEv1Attribute attr;

        private LifeType(int value) {
            this.attr = new IKEv1Attribute(value);
            lookup.put(value, this);
        }

        @Override
        public IKEv1Attribute getAttribute() {
            return attr;
        }
    }

    public enum Cipher implements FixedValueIKEv1Attribute {
        DES_CBC(0x80010001),
        IDEA_CBC(0x80010002),
        Blowfish_CBC(0x80010003),
        RC5_R16_B64_CBC(0x80010004),
        TRIPPLEDES_CBC(0x80010005),
        CAST_CBC(0x80010006),
        AES_CBC(0x80010007);

        private final IKEv1Attribute attr;

        private Cipher(int value) {
            this.attr = new IKEv1Attribute(value);
            lookup.put(value, this);
        }

        @Override
        public IKEv1Attribute getAttribute() {
            return attr;
        }
    }

    public enum KeyLength implements FixedValueIKEv1Attribute {
        L128(0x800e0080),
        L192(0x800e00C0),
        L256(0x800e0100);

        private final IKEv1Attribute attr;

        private KeyLength(int value) {
            this.attr = new IKEv1Attribute(value);
            lookup.put(value, this);
        }

        @Override
        public IKEv1Attribute getAttribute() {
            return attr;
        }
    }

    public enum Hash implements FixedValueIKEv1Attribute {
        MD5(0x80020001),
        SHA1(0x80020002),
        TIGER(0x80020003);

        private final IKEv1Attribute attr;

        private Hash(int value) {
            this.attr = new IKEv1Attribute(value);
            lookup.put(value, this);
        }

        @Override
        public IKEv1Attribute getAttribute() {
            return attr;
        }
    }

    public static class Duration {

        public static IKEv1Attribute getAttribute(int duration) {
            if (duration > 0xFFFF) {
                throw new IllegalArgumentException("Duration too large.");
            }
            return new IKEv1Attribute(0x800c << 16 | duration);
        }
    }

}
