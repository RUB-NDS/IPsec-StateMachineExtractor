/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp.v2;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPParsingException;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPSerializable;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class TrafficSelector implements ISAKMPSerializable {

    private byte tsType = 7; //ipv4 address
    private byte IPProtocolID = 0; //can do all protos tcp, udp..
    private byte[] length = new byte[]{0x00, 0x10};
    private byte[] startPort = new byte[]{0x00, 0x00};
    private byte[] endPort = DatatypeHelper.hexDumpToByteArray("FFFF");
    private byte[] startAddress = new byte[]{0x00, 0x00, 0x00, 0x00};
    private byte[] endAddress = DatatypeHelper.hexDumpToByteArray("FFFFFFFF");

    public TrafficSelector() {
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        baos.write(this.tsType);
        baos.write(this.IPProtocolID);
        baos.write(this.length, 0, this.length.length);
        baos.write(this.startPort, 0, this.startPort.length);
        baos.write(this.endPort, 0, this.endPort.length);
        baos.write(this.startAddress, 0, this.startAddress.length);
        baos.write(this.endAddress, 0, this.endAddress.length);
    }

    public static TrafficSelector fromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        TrafficSelector ts = new TrafficSelector();
        ts.fillFromStream(bais);
        return ts;
    }

    protected void fillFromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        bais.skip(0x10);
        //byte[] buffer = read4ByteFromStream(bais);
        /**
         * int readBytes; try { readBytes = bais.read(buffer); } catch
         * (IOException ex) { throw new ISAKMPParsingException(ex); } if
         * (readBytes < length - ISAKMP_PAYLOAD_HEADER_LEN) { throw new
         * ISAKMPParsingException("Input stream ended early after " + readBytes
         * + " bytes (should read " + (length - ISAKMP_PAYLOAD_HEADER_LEN) +
         * "bytes)!"); } if (getTSNumber() != buffer[0]) { throw new
         * ISAKMPParsingException("Only one Traffic Selector parsing is
         * supported!"); } traffic.fromStream(bais);
        *
         */
    }

    @Override
    public int getLength() {
        return 0x10;
    }
}
