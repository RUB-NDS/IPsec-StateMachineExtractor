/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.AuthAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.CipherAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.DHGroupAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.LifeDurationAttribute;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.HashAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.KeyLengthAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.LifeTypeAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.ProposalPayloadv2;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.SecurityAssociationPayloadv2;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.TransformPayloadv2;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.TransformTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ipsec.ESPTransformIDEnum;
import de.rub.nds.ipsec.statemachineextractor.ipsec.ProtocolTransformIDEnum;
import de.rub.nds.ipsec.statemachineextractor.ipsec.attributes.AuthenticationAlgorithmAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ipsec.attributes.EncapsulationModeAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ipsec.attributes.SALifeDurationBasicAttribute;
import de.rub.nds.ipsec.statemachineextractor.ipsec.attributes.SALifeTypeAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ProposalPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ProtocolIDEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.SecurityAssociationPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.TransformPayload;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class SecurityAssociationPayloadFactory {

    private SecurityAssociationPayloadFactory() {
    }

    public static SecurityAssociationPayload createV1P1SA(AuthAttributeEnum authMethod, CipherAttributeEnum cipher, de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.KeyLengthAttributeEnum keylength, HashAttributeEnum hash, DHGroupAttributeEnum group, LifeTypeAttributeEnum lifetype, LifeDurationAttribute duration) {
        TransformPayload transformPayload = new TransformPayload();
        transformPayload.addAttribute(cipher);
        if (!cipher.isFixedKeySize()) {
            transformPayload.addAttribute(keylength);
        }
        transformPayload.addAttribute(hash);
        transformPayload.addAttribute(group);
        transformPayload.addAttribute(authMethod);
        transformPayload.addAttribute(lifetype);
        transformPayload.addAttribute(duration);
        ProposalPayload proposalPayload = new ProposalPayload();
        proposalPayload.addTransform(transformPayload);
        SecurityAssociationPayload securityAssociationPayload = new SecurityAssociationPayload();
        securityAssociationPayload.setIdentityOnlyFlag(true);
        securityAssociationPayload.addProposalPayload(proposalPayload);
        return securityAssociationPayload;
    }

    public static SecurityAssociationPayload createV1P2ESPSA(ESPTransformIDEnum cipher, EncapsulationModeAttributeEnum encap, de.rub.nds.ipsec.statemachineextractor.ipsec.attributes.KeyLengthAttributeEnum keylength, AuthenticationAlgorithmAttributeEnum auth, SALifeTypeAttributeEnum lifetype, SALifeDurationBasicAttribute duration) {
        TransformPayload transformPayload = new TransformPayload();
        transformPayload.setTransformId(cipher.toProtocolTransformIDEnum());
        transformPayload.addAttribute(encap);
        transformPayload.addAttribute(lifetype);
        transformPayload.addAttribute(duration);
        if (auth != null) {
            transformPayload.addAttribute(auth);
        }
        if (!cipher.isIsFixedKeySize()) {
            transformPayload.addAttribute(keylength);
        }
        ProposalPayload proposalPayload = new ProposalPayload();
        proposalPayload.addTransform(transformPayload);
        proposalPayload.setSPIRandom();
        proposalPayload.setProtocolId(ProtocolIDEnum.IPSEC_ESP);
        SecurityAssociationPayload securityAssociationPayload = new SecurityAssociationPayload();
        securityAssociationPayload.setIdentityOnlyFlag(true);
        securityAssociationPayload.addProposalPayload(proposalPayload);
        return securityAssociationPayload;
    }

    public static SecurityAssociationPayloadv2 createV2P1SA(ProtocolTransformIDEnum transformIDENC, ProtocolTransformIDEnum transformIDPRF, ProtocolTransformIDEnum transformIDINTEG, ProtocolTransformIDEnum transformIDDH, de.rub.nds.ipsec.statemachineextractor.ike.v2.attributes.KeyLengthAttributeEnum keylength) {
        TransformPayloadv2 transformPayloadENC = new TransformPayloadv2();
        transformPayloadENC.setTransformType(TransformTypeEnum.ENCR);
        transformPayloadENC.setTransformId(transformIDENC);
        transformPayloadENC.addAttribute(keylength);

        TransformPayloadv2 transformPayloadPRF = new TransformPayloadv2();
        transformPayloadPRF.setTransformType(TransformTypeEnum.PRF);
        transformPayloadPRF.setTransformId(transformIDPRF);

        TransformPayloadv2 transformPayloadINTEG = new TransformPayloadv2();
        transformPayloadINTEG.setTransformType(TransformTypeEnum.INTEG);
        transformPayloadINTEG.setTransformId(transformIDINTEG);

        TransformPayloadv2 transformPayloadDH = new TransformPayloadv2();
        transformPayloadDH.setTransformType(TransformTypeEnum.DH);
        transformPayloadDH.setTransformId(transformIDDH);

        ProposalPayloadv2 proposalPayload = new ProposalPayloadv2();
        proposalPayload.setProposalNumber((byte) 1); //also works with proposal number 0
        proposalPayload.addTransform(transformPayloadENC);
        proposalPayload.addTransform(transformPayloadPRF);
        proposalPayload.addTransform(transformPayloadINTEG);
        proposalPayload.addTransform(transformPayloadDH);

        SecurityAssociationPayloadv2 securityAssociationPayload = new SecurityAssociationPayloadv2();
        securityAssociationPayload.addProposalPayloadv2(proposalPayload);
        return securityAssociationPayload;
    }

    public static SecurityAssociationPayloadv2 createV2P2SA(ProtocolTransformIDEnum transformIDENC, ProtocolTransformIDEnum transformIDINTEG, ProtocolTransformIDEnum transformIDESN, de.rub.nds.ipsec.statemachineextractor.ike.v2.attributes.KeyLengthAttributeEnum keylength) {
        TransformPayloadv2 transformPayloadENC = new TransformPayloadv2();
        transformPayloadENC.setTransformType(TransformTypeEnum.ENCR);
        transformPayloadENC.setTransformId(transformIDENC);
        transformPayloadENC.addAttribute(keylength);

        TransformPayloadv2 transformPayloadINTEG = new TransformPayloadv2();
        transformPayloadINTEG.setTransformType(TransformTypeEnum.INTEG);
        transformPayloadINTEG.setTransformId(transformIDINTEG);

        TransformPayloadv2 transformPayloadESN = new TransformPayloadv2();
        transformPayloadESN.setTransformType(TransformTypeEnum.ESN);
        transformPayloadESN.setTransformId(transformIDESN);

        ProposalPayloadv2 proposalPayload = new ProposalPayloadv2();
        proposalPayload.setProposalNumber((byte) 1);
        proposalPayload.setProtocolId(ProtocolIDEnum.IPSEC_ESP);
        proposalPayload.setSPIRandom();
        proposalPayload.addTransform(transformPayloadENC);
        proposalPayload.addTransform(transformPayloadINTEG);
        proposalPayload.addTransform(transformPayloadESN);

        SecurityAssociationPayloadv2 securityAssociationPayload = new SecurityAssociationPayloadv2();
        securityAssociationPayload.addProposalPayloadv2(proposalPayload);
        return securityAssociationPayload;
    }

    public static final SecurityAssociationPayload V1_P1_PSK_DES_MD5_G1 = createV1P1SA(AuthAttributeEnum.PSK, CipherAttributeEnum.DES_CBC, null, HashAttributeEnum.MD5, DHGroupAttributeEnum.GROUP1, LifeTypeAttributeEnum.SECONDS, LifeDurationAttribute.get(28800));
    public static final SecurityAssociationPayload V1_P1_PSK_AES128_SHA1_G2 = createV1P1SA(AuthAttributeEnum.PSK, CipherAttributeEnum.AES_CBC, KeyLengthAttributeEnum.L128, HashAttributeEnum.SHA1, DHGroupAttributeEnum.GROUP2, LifeTypeAttributeEnum.SECONDS, LifeDurationAttribute.get(28800));
    public static final SecurityAssociationPayload V1_P1_PSK_AES128_SHA1_G5 = createV1P1SA(AuthAttributeEnum.PSK, CipherAttributeEnum.AES_CBC, KeyLengthAttributeEnum.L128, HashAttributeEnum.SHA1, DHGroupAttributeEnum.GROUP5, LifeTypeAttributeEnum.SECONDS, LifeDurationAttribute.get(28800));
    public static final SecurityAssociationPayload V1_P1_PKE_AES128_SHA1_G5 = createV1P1SA(AuthAttributeEnum.PKE, CipherAttributeEnum.AES_CBC, KeyLengthAttributeEnum.L128, HashAttributeEnum.SHA1, DHGroupAttributeEnum.GROUP5, LifeTypeAttributeEnum.SECONDS, LifeDurationAttribute.get(28800));
    public static final SecurityAssociationPayload V1_P1_RPKE_AES128_SHA1_G5 = createV1P1SA(AuthAttributeEnum.RevPKE, CipherAttributeEnum.AES_CBC, KeyLengthAttributeEnum.L128, HashAttributeEnum.SHA1, DHGroupAttributeEnum.GROUP5, LifeTypeAttributeEnum.SECONDS, LifeDurationAttribute.get(28800));

    public static final SecurityAssociationPayloadv2 V2_P1_AES_128_CBC_SHA1 = createV2P1SA(ProtocolTransformIDEnum.IKEV2_ENC_AES_CBC, ProtocolTransformIDEnum.IKEV2_PRF_HMAC_SHA1, ProtocolTransformIDEnum.IKEV2_INTEG_HMAC_SHA1_96, ProtocolTransformIDEnum.IKEV2_DH_1024_MODP, de.rub.nds.ipsec.statemachineextractor.ike.v2.attributes.KeyLengthAttributeEnum.L128);
    public static final SecurityAssociationPayloadv2 V2_P2_AES_128_CBC_SHA1_ESN = createV2P2SA(ProtocolTransformIDEnum.IKEV2_ENC_AES_CBC, ProtocolTransformIDEnum.IKEV2_INTEG_HMAC_SHA1_96, ProtocolTransformIDEnum.IKEV2_ESN_NO_X_SN, de.rub.nds.ipsec.statemachineextractor.ike.v2.attributes.KeyLengthAttributeEnum.L128);

    public static SecurityAssociationPayload getV1_P2_ESP_TUNNEL_AES128_SHA1() {
        return createV1P2ESPSA(ESPTransformIDEnum.AES, EncapsulationModeAttributeEnum.Tunnel, de.rub.nds.ipsec.statemachineextractor.ipsec.attributes.KeyLengthAttributeEnum.L128, AuthenticationAlgorithmAttributeEnum.HMAC_SHA, SALifeTypeAttributeEnum.SECONDS, SALifeDurationBasicAttribute.get(3600));
    }

    public static SecurityAssociationPayload getV1_P2_ESP_TUNNEL_AES128_NONE() {
        return createV1P2ESPSA(ESPTransformIDEnum.AES, EncapsulationModeAttributeEnum.Tunnel, de.rub.nds.ipsec.statemachineextractor.ipsec.attributes.KeyLengthAttributeEnum.L128, null, SALifeTypeAttributeEnum.SECONDS, SALifeDurationBasicAttribute.get(3600));
    }
}
