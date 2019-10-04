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
//    IKEv1_MM_SA,
//    IKEv1_MM_KE,
//    IKEv1_MM_HASH,
    IKEv1_AM_SA_KE_No_ID_V_V_HASH,
    IKEv1_INFO_InvalidPayloadType,
    IKEv1_INFO_DoiNotSupported,
    IKEv1_INFO_SituationNotSupported,
    IKEv1_INFO_InvalidCookie,
    IKEv1_INFO_InvalidMajorVersion,
    IKEv1_INFO_InvalidMinorVersion,
    IKEv1_INFO_InvalidExchangeType,
    IKEv1_INFO_InvalidFlags,
    IKEv1_INFO_InvalidMessageId,
    IKEv1_INFO_InvalidProtocolId,
    IKEv1_INFO_InvalidSpi,
    IKEv1_INFO_InvalidTransformId,
    IKEv1_INFO_AttributesNotSupported,
    IKEv1_INFO_NoProposalChosen,
    IKEv1_INFO_BadProposalSyntax,
    IKEv1_INFO_PayloadMalformed,
    IKEv1_INFO_InvalidKeyInformation,
    IKEv1_INFO_InvalidIdInformation,
    IKEv1_INFO_InvalidCertEncoding,
    IKEv1_INFO_InvalidCertificate,
    IKEv1_INFO_CertTypeUnsupported,
    IKEv1_INFO_InvalidCertAuthority,
    IKEv1_INFO_InvalidHashInformation,
    IKEv1_INFO_AuthenticationFailed,
    IKEv1_INFO_InvalidSignature,
    IKEv1_INFO_AddressNotification,
    IKEv1_INFO_NotifySaLifetime,
    IKEv1_INFO_CertificateUnavailable,
    IKEv1_INFO_UnsupportedExchangeType,
    IKEv1_INFO_UnequalPayloadLengths,
    IKEv1_INFO_Connected;
}
