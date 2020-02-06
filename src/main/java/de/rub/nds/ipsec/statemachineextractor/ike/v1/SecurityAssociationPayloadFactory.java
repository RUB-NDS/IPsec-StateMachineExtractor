/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.AuthAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.CipherAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.DHGroupAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.LifeDurationAttribute;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.HashAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.KeyLengthAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.LifeTypeAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ipsec.ESPTransformIDEnum;
import de.rub.nds.ipsec.statemachineextractor.ipsec.attributes.AuthenticationAlgorithmAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ipsec.attributes.EncapsulationModeAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ipsec.attributes.SALifeDurationAttribute;
import de.rub.nds.ipsec.statemachineextractor.ipsec.attributes.SALifeTypeAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ProposalPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ProtocolIDEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.SecurityAssociationPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.TransformPayload;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class SecurityAssociationPayloadFactory {

    private SecurityAssociationPayloadFactory() {
    }

    public static SecurityAssociationPayload createP1SA(AuthAttributeEnum authMethod, CipherAttributeEnum cipher, de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.KeyLengthAttributeEnum keylength, HashAttributeEnum hash, DHGroupAttributeEnum group, LifeTypeAttributeEnum lifetype, LifeDurationAttribute duration) {
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

    public static SecurityAssociationPayload createP2ESPSA(ESPTransformIDEnum cipher, EncapsulationModeAttributeEnum encap, de.rub.nds.ipsec.statemachineextractor.ipsec.attributes.KeyLengthAttributeEnum keylength, AuthenticationAlgorithmAttributeEnum auth, SALifeTypeAttributeEnum lifetype, SALifeDurationAttribute duration) {
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

    public static final SecurityAssociationPayload P1_PSK_DES_MD5_G1      = createP1SA(AuthAttributeEnum.PSK, CipherAttributeEnum.DES_CBC, null, HashAttributeEnum.MD5, DHGroupAttributeEnum.GROUP1, LifeTypeAttributeEnum.SECONDS, LifeDurationAttribute.get(28800));
    public static final SecurityAssociationPayload P1_PSK_AES128_SHA1_G2  = createP1SA(AuthAttributeEnum.PSK, CipherAttributeEnum.AES_CBC, KeyLengthAttributeEnum.L128, HashAttributeEnum.SHA1, DHGroupAttributeEnum.GROUP2, LifeTypeAttributeEnum.SECONDS, LifeDurationAttribute.get(28800));
    public static final SecurityAssociationPayload P1_PSK_AES128_SHA1_G5  = createP1SA(AuthAttributeEnum.PSK, CipherAttributeEnum.AES_CBC, KeyLengthAttributeEnum.L128, HashAttributeEnum.SHA1, DHGroupAttributeEnum.GROUP5, LifeTypeAttributeEnum.SECONDS, LifeDurationAttribute.get(28800));
    public static final SecurityAssociationPayload P1_PKE_AES128_SHA1_G5  = createP1SA(AuthAttributeEnum.PKE, CipherAttributeEnum.AES_CBC, KeyLengthAttributeEnum.L128, HashAttributeEnum.SHA1, DHGroupAttributeEnum.GROUP5, LifeTypeAttributeEnum.SECONDS, LifeDurationAttribute.get(28800));
    public static final SecurityAssociationPayload P1_RPKE_AES128_SHA1_G5 = createP1SA(AuthAttributeEnum.RevPKE, CipherAttributeEnum.AES_CBC, KeyLengthAttributeEnum.L128, HashAttributeEnum.SHA1, DHGroupAttributeEnum.GROUP5, LifeTypeAttributeEnum.SECONDS, LifeDurationAttribute.get(28800));

    public static SecurityAssociationPayload getP2_ESP_TUNNEL_AES128_SHA1() {
        return createP2ESPSA(ESPTransformIDEnum.AES, EncapsulationModeAttributeEnum.Tunnel, de.rub.nds.ipsec.statemachineextractor.ipsec.attributes.KeyLengthAttributeEnum.L128, AuthenticationAlgorithmAttributeEnum.HMAC_SHA, SALifeTypeAttributeEnum.SECONDS, SALifeDurationAttribute.get(3600));
    }

    public static SecurityAssociationPayload getP2_ESP_TUNNEL_AES128_NONE() {
        return createP2ESPSA(ESPTransformIDEnum.AES, EncapsulationModeAttributeEnum.Tunnel, de.rub.nds.ipsec.statemachineextractor.ipsec.attributes.KeyLengthAttributeEnum.L128, null, SALifeTypeAttributeEnum.SECONDS, SALifeDurationAttribute.get(3600));
    }
}
