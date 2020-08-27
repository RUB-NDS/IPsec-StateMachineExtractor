/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.TrafficSelectorSubstructureTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.IKEv2ParsingException;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.IKEv2Serializable;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import de.rub.nds.ipsec.statemachineextractor.util.IPProtocolsEnum;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class TrafficSelectorSubstructure implements IKEv2Serializable {

    private TrafficSelectorSubstructureTypeEnum TSType = TrafficSelectorSubstructureTypeEnum.TS_IPV4_ADDR_RANGE;
    private IPProtocolsEnum IPProtocolID = IPProtocolsEnum.ANY;
    private final byte[] length = new byte[]{0x00, 0x10};
    private final byte[] startPort = new byte[2];
    private final byte[] endPort = DatatypeHelper.hexDumpToByteArray("FFFF");
    private byte[] startAddress = new byte[4];
    private byte[] endAddress = DatatypeHelper.hexDumpToByteArray("FFFFFFFF");

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        baos.write(this.TSType.getValue());
        baos.write(this.IPProtocolID.value());
        baos.write(this.length, 0, this.length.length);
        baos.write(this.startPort, 0, this.startPort.length);
        baos.write(this.endPort, 0, this.endPort.length);
        baos.write(this.startAddress, 0, this.startAddress.length);
        baos.write(this.endAddress, 0, this.endAddress.length);
    }

    public static TrafficSelectorSubstructure fromStream(ByteArrayInputStream bais) throws IKEv2ParsingException {
        TrafficSelectorSubstructure ts = new TrafficSelectorSubstructure();
        ts.fillFromStream(bais);
        return ts;
    }

    protected void fillFromStream(ByteArrayInputStream bais) throws IKEv2ParsingException {
        byte[] buffer = new byte[4];
        readFromStream(bais, buffer);
        if (TrafficSelectorSubstructureTypeEnum.get(buffer[0]) == null) {
            throw new IKEv2ParsingException("Traffic selector types other than TS_IPV4_ADDR_RANGE (0x07) or TS_IPV6_ADDR_RANGE (0x08)are not supported!");
        }
        this.TSType = TrafficSelectorSubstructureTypeEnum.get(buffer[0]);
        this.IPProtocolID = IPProtocolsEnum.byNumber(buffer[1]);
        if (buffer[2] != 0x00
                || (this.TSType == TrafficSelectorSubstructureTypeEnum.TS_IPV4_ADDR_RANGE && buffer[3] != 0x10)
                || this.TSType == TrafficSelectorSubstructureTypeEnum.TS_IPV6_ADDR_RANGE && buffer[3] != 0x28) {
            throw new IKEv2ParsingException("Length of this Traffic Selector Substructure does not fit to its type!");
        }
        this.length[1] = buffer[3];
        readFromStream(bais, this.startPort);
        readFromStream(bais, this.endPort);
        if (this.TSType == TrafficSelectorSubstructureTypeEnum.TS_IPV4_ADDR_RANGE) {
            startAddress = new byte[4];
            endAddress = new byte[4];
        } else if (this.TSType == TrafficSelectorSubstructureTypeEnum.TS_IPV6_ADDR_RANGE) {
            startAddress = new byte[16];
            endAddress = new byte[16];
        }
        readFromStream(bais, this.startAddress);
        readFromStream(bais, this.endAddress);
    }

    private void readFromStream(ByteArrayInputStream bais, byte[] array) throws IKEv2ParsingException {
        int read;
        try {
            read = bais.read(array);
            if (read != array.length) {
                throw new IKEv2ParsingException("Reading from InputStream failed!");
            }
        } catch (IOException ex) {
            throw new IKEv2ParsingException(ex);
        }
    }

    @Override
    public int getLength() {
        return 8 + this.startAddress.length + this.endAddress.length;
    }
}
