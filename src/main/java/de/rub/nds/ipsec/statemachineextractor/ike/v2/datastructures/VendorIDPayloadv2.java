/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures;

import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKEParsingException;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEPayloadTypeEnum;
import static de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper.hexDumpToByteArray;
import java.io.ByteArrayInputStream;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class VendorIDPayloadv2 extends SimpleBinaryIKEv2Payload {

    public VendorIDPayloadv2() {
        super(IKEPayloadTypeEnum.VendorIDv2);
    }

    private VendorIDPayloadv2(String vendorID) {
        super(IKEPayloadTypeEnum.VendorIDv2);
        setVendorID(hexDumpToByteArray(vendorID));
    }
    
    public byte[] getVendorID() {
        return getBinaryData();
    }

    public final void setVendorID(byte[] vendorID) {
        setBinaryData(vendorID);
    }

    @Override
    public String toString() {
        return "V";
    }

    public static VendorIDPayloadv2 fromStream(ByteArrayInputStream bais) throws GenericIKEParsingException {
        VendorIDPayloadv2 vendorIDPayload = new VendorIDPayloadv2();
        SimpleBinaryIKEv2Payload.fromStream(bais, vendorIDPayload);
        return vendorIDPayload;
    }

    public static VendorIDPayloadv2 CiscoDeleteReasonSupported = new VendorIDPayloadv2("434953434f2d44454c4554452d524541534f4e");
    public static VendorIDPayloadv2 CiscoFlexVPNSupported = new VendorIDPayloadv2("464c455856504e2d535550504f52544544");    
}
