/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;

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

    /*
     * @see https://stackoverflow.com/a/9855338
     */
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    public static String byteArrayToHexDump(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static final byte[] read4ByteFromStream(ByteArrayInputStream bais) throws IOException {
        byte[] buffer = new byte[4];
        int read = bais.read(buffer);
        if (read != 4) {
            throw new IOException("Reading from InputStream failed!");
        }
        return buffer;
    }
}
