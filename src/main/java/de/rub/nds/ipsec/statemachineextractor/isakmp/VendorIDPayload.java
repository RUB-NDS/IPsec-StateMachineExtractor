/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import static de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper.hexDumpToByteArray;
import java.io.ByteArrayInputStream;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class VendorIDPayload extends SimpleBinaryPayload {

    public VendorIDPayload() {
        super(PayloadTypeEnum.VendorID);
    }

    public byte[] getVendorID() {
        return getBinaryData();
    }

    public void setVendorID(byte[] vendorID) {
        setBinaryData(vendorID);
    }

    private VendorIDPayload(String vendorID) {
        super(PayloadTypeEnum.VendorID);
        _setVendorID(hexDumpToByteArray(vendorID));
    }

    private void _setVendorID(byte[] vendorID) {
        setBinaryData(vendorID);
    }

    @Override
    public String toString() {
        return "V";
    }
    
    public static VendorIDPayload fromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        VendorIDPayload vendorIDpayload = new VendorIDPayload();
        SimpleBinaryPayload.fromStream(bais, vendorIDpayload);
        return vendorIDpayload;
    }

    public static VendorIDPayload DeadPeerDetection = new VendorIDPayload("afcad71368a1f1c96b8696fc77570100");
    public static VendorIDPayload XAUTH = new VendorIDPayload("09002689dfd6b712");
    public static VendorIDPayload CiscoUnity10 = new VendorIDPayload("12f5f28c457168a9702d9fe274cc0100");
}
