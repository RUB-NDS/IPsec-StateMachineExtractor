/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.learning;

import de.learnlib.api.exception.SULException;
import de.learnlib.mapper.api.ContextExecutableInput;
import de.learnlib.mapper.api.SULMapper;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.IKEv1Attribute;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.IKEv1Handshake;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ExchangeTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.HashPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPMessage;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPParsingException;
import de.rub.nds.ipsec.statemachineextractor.isakmp.IdentificationPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.KeyExchangePayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.NoncePayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ProposalPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.SecurityAssociationPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.TransformPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.VendorIDPayload;
import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEMessageMapper implements SULMapper<IKEAlphabetEnum, IKEAlphabetEnum, ContextExecutableInput<ISAKMPMessage, IKEv1Handshake>, ISAKMPMessage> {

    @Override
    public ContextExecutableInput<ISAKMPMessage, IKEv1Handshake> mapInput(IKEAlphabetEnum abstractInput) {
        return (IKEv1Handshake handshake) -> {
            ISAKMPMessage msg = new ISAKMPMessage();
            try {
                switch (abstractInput) {
                    case IKEv1_MM_SA_PKE:
                        msg.setExchangeType(ExchangeTypeEnum.IdentityProtection);
                        msg.addPayload(getPKESecurityAssociationPayload());
                        break;
                    case IKEv1_MM_KEX_PKE:
                        msg.setExchangeType(ExchangeTypeEnum.IdentityProtection);
                        KeyExchangePayload keyExchangePayload = handshake.prepareKeyExchangePayload();
                        msg.addPayload(keyExchangePayload);
                        IdentificationPayload identificationPayload = handshake.prepareIdentificationPayload();
                        msg.addPayload(identificationPayload);
                        NoncePayload noncePayload = handshake.prepareNoncePayload();
                        msg.addPayload(noncePayload);
                        msg.addPayload(VendorIDPayload.DeadPeerDetection);
                        break;
                    case IKEv1_MM_HASH:
                        msg.setExchangeType(ExchangeTypeEnum.IdentityProtection);
                        HashPayload hashPayload = new HashPayload();
                        handshake.prepareHashPayload();
                        msg.addPayload(hashPayload);
                        break;
                    default:
                        throw new UnsupportedOperationException("Not supported yet.");
                }
                return handshake.exchangeMessage(msg);
            } catch (IOException | ISAKMPParsingException | GeneralSecurityException ex) {
                throw new SULException(ex);
            }
        };
    }

    @Override
    public IKEAlphabetEnum mapOutput(ISAKMPMessage concreteOutput) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public static SecurityAssociationPayload getPKESecurityAssociationPayload() {
        TransformPayload transformPayload = new TransformPayload();
        transformPayload.setTransformNumber((byte) 1);
        transformPayload.addIKEAttribute(IKEv1Attribute.Cipher.AES_CBC.getAttribute());
        transformPayload.addIKEAttribute(IKEv1Attribute.KeyLength.L128.getAttribute());
        transformPayload.addIKEAttribute(IKEv1Attribute.Hash.SHA1.getAttribute());
        transformPayload.addIKEAttribute(IKEv1Attribute.DH.GROUP5.getAttribute());
        transformPayload.addIKEAttribute(IKEv1Attribute.Auth.PKE.getAttribute());
        transformPayload.addIKEAttribute(IKEv1Attribute.LifeType.SECONDS.getAttribute());
        transformPayload.addIKEAttribute(IKEv1Attribute.Duration.getAttribute(28800));
        ProposalPayload proposalPayload = new ProposalPayload();
        proposalPayload.addTransform(transformPayload);
        SecurityAssociationPayload securityAssociationPayload = new SecurityAssociationPayload();
        securityAssociationPayload.setIdentityOnlyFlag(true);
        securityAssociationPayload.addProposalPayload(proposalPayload);
        return securityAssociationPayload;
    }
    
    public static SecurityAssociationPayload getPSKSecurityAssociationPayload() {
        TransformPayload transformPayload = new TransformPayload();
        transformPayload.setTransformNumber((byte) 1);
        transformPayload.addIKEAttribute(IKEv1Attribute.Cipher.AES_CBC.getAttribute());
        transformPayload.addIKEAttribute(IKEv1Attribute.KeyLength.L128.getAttribute());
        transformPayload.addIKEAttribute(IKEv1Attribute.Hash.SHA1.getAttribute());
        transformPayload.addIKEAttribute(IKEv1Attribute.DH.GROUP5.getAttribute());
        transformPayload.addIKEAttribute(IKEv1Attribute.Auth.PSK.getAttribute());
        transformPayload.addIKEAttribute(IKEv1Attribute.LifeType.SECONDS.getAttribute());
        transformPayload.addIKEAttribute(IKEv1Attribute.Duration.getAttribute(28800));
        ProposalPayload proposalPayload = new ProposalPayload();
        proposalPayload.addTransform(transformPayload);
        SecurityAssociationPayload securityAssociationPayload = new SecurityAssociationPayload();
        securityAssociationPayload.setIdentityOnlyFlag(true);
        securityAssociationPayload.addProposalPayload(proposalPayload);
        return securityAssociationPayload;
    }

}
