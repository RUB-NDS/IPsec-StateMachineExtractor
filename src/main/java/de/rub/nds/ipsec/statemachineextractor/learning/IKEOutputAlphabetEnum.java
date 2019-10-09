/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.learning;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public enum IKEOutputAlphabetEnum {
    NO_RESPONSE,
    PARSING_ERROR,
//    v1_MM_SA,
//    v1_MM_KE,
//    v1_MM_HASH,
    v1_AM_SA_KE_No_ID_V_V_HASH,
    v1_INFO_HASH_DEL,
    v1_INFO_InvalidPayloadType,
    v1_INFO_DoiNotSupported,
    v1_INFO_SituationNotSupported,
    v1_INFO_InvalidCookie,
    v1_INFO_InvalidMajorVersion,
    v1_INFO_InvalidMinorVersion,
    v1_INFO_InvalidExchangeType,
    v1_INFO_InvalidFlags,
    v1_INFO_InvalidMessageId,
    v1_INFO_InvalidProtocolId,
    v1_INFO_InvalidSpi,
    v1_INFO_InvalidTransformId,
    v1_INFO_AttributesNotSupported,
    v1_INFO_NoProposalChosen,
    v1_INFO_BadProposalSyntax,
    v1_INFO_PayloadMalformed,
    v1_INFO_InvalidKeyInformation,
    v1_INFO_InvalidIdInformation,
    v1_INFO_InvalidCertEncoding,
    v1_INFO_InvalidCertificate,
    v1_INFO_CertTypeUnsupported,
    v1_INFO_InvalidCertAuthority,
    v1_INFO_InvalidHashInformation,
    v1_INFO_AuthenticationFailed,
    v1_INFO_InvalidSignature,
    v1_INFO_AddressNotification,
    v1_INFO_NotifySaLifetime,
    v1_INFO_CertificateUnavailable,
    v1_INFO_UnsupportedExchangeType,
    v1_INFO_UnequalPayloadLengths,
    v1_INFO_Connected;
}
