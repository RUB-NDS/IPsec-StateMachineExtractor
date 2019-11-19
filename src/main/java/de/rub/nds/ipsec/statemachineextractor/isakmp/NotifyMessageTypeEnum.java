/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public enum NotifyMessageTypeEnum {

    InvalidPayloadType(1),
    DoiNotSupported(2),
    SituationNotSupported(3),
    InvalidCookie(4),
    InvalidMajorVersion(5),
    InvalidMinorVersion(6),
    InvalidExchangeType(7),
    InvalidFlags(8),
    InvalidMessageId(9),
    InvalidProtocolId(10),
    InvalidSpi(11),
    InvalidTransformId(12),
    AttributesNotSupported(13),
    NoProposalChosen(14),
    BadProposalSyntax(15),
    PayloadMalformed(16),
    InvalidKeyInformation(17),
    InvalidIdInformation(18),
    InvalidCertEncoding(19),
    InvalidCertificate(20),
    CertTypeUnsupported(21),
    InvalidCertAuthority(22),
    InvalidHashInformation(23),
    AuthenticationFailed(24),
    InvalidSignature(25),
    AddressNotification(26),
    NotifySaLifetime(27),
    CertificateUnavailable(28),
    UnsupportedExchangeType(29),
    UnequalPayloadLengths(30),
    Connected(16384),
    ResponderLifetime(24576),
    ReplayStatus(24577),
    InitialContact(24578);

    private final int value;

    private NotifyMessageTypeEnum(int value) {
        this.value = value;
    }

    public byte[] getValue() {
        return new byte[]{(byte) ((value >> 8) & 0xFF), (byte) (value & 0xFF)};
    }

    // Reverse-lookup map
    private static final Map<Integer, NotifyMessageTypeEnum> lookup = new HashMap<Integer, NotifyMessageTypeEnum>();

    static {
        for (NotifyMessageTypeEnum type : NotifyMessageTypeEnum.values()) {
            lookup.put(type.value, type);
        }
    }

    public static NotifyMessageTypeEnum get(byte[] value) {
        if (value.length != 2) {
            throw new IllegalArgumentException("NotifyMessageType is two bytes!");
        }
        int low = value[1] >= 0 ? value[1] : 256 + value[1];
        int high = value[0] >= 0 ? value[0] : 256 + value[0];
        NotifyMessageTypeEnum type = lookup.get(low | (high << 8));
        if (type == null) {
            throw new IllegalArgumentException("Encountered unknown NotifyMessageType!");
        }
        return type;
    }

}
