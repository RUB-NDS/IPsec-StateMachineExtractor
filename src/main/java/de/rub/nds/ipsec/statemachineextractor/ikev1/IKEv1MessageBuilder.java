/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ikev1;

import de.rub.nds.ipsec.statemachineextractor.isakmp.ExchangeTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPMessage;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPParsingException;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.PayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.SecurityAssociationPayload;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.Arrays;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv1MessageBuilder {

    private IKEv1MessageBuilder() {
    }

    public static ISAKMPMessage fromByteArray(byte[] bytes) throws ISAKMPParsingException {
        if (bytes.length < ISAKMPMessage.ISAKMP_HEADER_LEN) {
            throw new ISAKMPParsingException("Not enough bytes supplied to build an ISAKMPMessage!");
        }
        if (ExchangeTypeEnum.get(bytes[18]) != ExchangeTypeEnum.IdentityProtection) {
            throw new UnsupportedOperationException("Not supported yet.");
        }
        ISAKMPMessage message = new ISAKMPMessage();
        message.setInitiatorCookie(Arrays.copyOfRange(bytes, 0, 8));
        message.setResponderCookie(Arrays.copyOfRange(bytes, 8, 16));
        message.setVersion(bytes[17]);
        message.setExchangeType(ExchangeTypeEnum.get(bytes[18]));
        message.setEncryptedFlag((bytes[19] & 1) > 0);
        message.setCommitFlag((bytes[19] & 2) > 0);
        message.setAuthenticationOnlyFlag((bytes[19] & 4) > 0);
        message.setMessageId(Arrays.copyOfRange(bytes, 20, 24));
        int messageLength = new BigInteger(Arrays.copyOfRange(bytes, 24, 28)).intValue();

        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        bais.skip(ISAKMPMessage.ISAKMP_HEADER_LEN);
        PayloadTypeEnum nextPayload = PayloadTypeEnum.get(bytes[16]);
        while (nextPayload != PayloadTypeEnum.NONE) {
            ISAKMPPayload payload;
            switch (nextPayload) {
                case SecurityAssociation:
                    payload = SecurityAssociationPayload.fromStream(bais);
                    break;
//                case KeyExchange:
//                    payload = KeyExchangePayload.fromStream(bais);
//                    break;
//                case Hash:
//                    payload = HashPayload.fromStream(bais);
//                    break;
                default:
                    throw new UnsupportedOperationException("Not supported yet.");
            }
            nextPayload = payload.getNextPayload();
            message.addPayload(payload);
        }
        if (messageLength != message.getLength()) {
            throw new ISAKMPParsingException("Message lengths differ - Computed: " + message.getLength() + "vs. Received: " + messageLength + "!");
        }
        return message;
    }

}
