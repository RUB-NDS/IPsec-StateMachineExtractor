/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.util;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public final class DatatypeHelper {

    private DatatypeHelper() {

    }

    public static final byte[] intTo4ByteArray(int value) {
        return new byte[]{
            (byte) (value >>> 24),
            (byte) (value >>> 16),
            (byte) (value >>> 8),
            (byte) value};
    }

    /*
     * @see https://stackoverflow.com/a/140861
     */
    public static final byte[] hexDumpToByteArray(String dump) {
        int len = dump.length();
        if ((len & 1) == 1) {
            throw new IllegalArgumentException("Hexdump is not of even length!");
        }
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(dump.charAt(i), 16) << 4)
                    + Character.digit(dump.charAt(i + 1), 16));
        }
        return data;
    }

}
