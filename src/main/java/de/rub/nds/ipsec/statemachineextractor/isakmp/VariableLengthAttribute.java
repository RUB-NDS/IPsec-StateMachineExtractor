/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import static de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper.read4ByteFromStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public abstract class VariableLengthAttribute implements ISAKMPAttribute {

    protected byte[] bytes;
    protected final short formatType;

    protected VariableLengthAttribute(short formatType, byte[] value) {
        if (value == null) {
            value = new byte[0];
        }
        if (value.length > 0xFFFF) {
            throw new IllegalArgumentException("Attribute value too long!");
        }
        this.formatType = formatType;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write((formatType << 16) + value.length);
        baos.write(value, 0, value.length);
        this.bytes = baos.toByteArray();
    }

    @Override
    public byte[] getBytes() {
        return bytes.clone();
    }

    public void fillFromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        int formatType, length;
        try {
            int header = ByteBuffer.wrap(read4ByteFromStream(bais)).getInt();
            formatType = header >>> 16;
            length = header & 0xFFFF;
        } catch (IOException ex) {
            throw new ISAKMPParsingException(ex);
        }
        if (formatType != this.formatType) {
            throw new ISAKMPParsingException("Wrong format type of attribute!");
        }
        byte[] value = new byte[length];
        if (bais.read(value, 0, length) != length) {
            throw new ISAKMPParsingException("InputStream ended early!");
        }
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(DatatypeHelper.intTo4ByteArray((formatType << 16) + length), 0, 4);
        baos.write(value, 0, value.length);
        this.bytes = baos.toByteArray();
    }

    @Override
    public int getLength() {
        return this.bytes.length;
    }

}
