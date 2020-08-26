/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike;

import de.rub.nds.ipsec.statemachineextractor.ike.DHGroupEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ProtocolIDEnum;
import de.rub.nds.ipsec.statemachineextractor.util.CryptoHelper;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.ECParameterSpec;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class SecurityAssociationSecrets implements Cloneable {

    private final DHGroupEnum DHGroup;
    private KeyPair dhKeyPair;
    private PublicKey peerPublicKey;
    private boolean isInitiatorNonceChosen = false;
    private byte[] dhSecret;
    private byte[] initiatorNonce = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private byte[] responderNonce = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private byte[] securityAssociationOfferBody;
    private byte[] keyExchangeData;
    private byte[] peerKeyExchangeData;
    private byte[] inboundSPI = new byte[]{0x7f, 0x7f, 0x7f, 0x7f};
    private byte[] outboundSPI = new byte[]{0x7f, 0x7f, 0x7f, 0x7f};
    private byte[] inboundKeyMaterial, outboundKeyMaterial;
    private ProtocolIDEnum protocol = ProtocolIDEnum.ISAKMP;

    public SecurityAssociationSecrets(DHGroupEnum DHGroup) {
        this.DHGroup = DHGroup;
    }

    @Override
    public SecurityAssociationSecrets clone() throws CloneNotSupportedException {
        return (SecurityAssociationSecrets) super.clone();
    }

    public DHGroupEnum getDHGroup() {
        return DHGroup;
    }

    public KeyPair getDhKeyPair() {
        return dhKeyPair;
    }

    public void setDhKeyPair(KeyPair dhKeyPair) {
        this.dhKeyPair = dhKeyPair;
    }

    public KeyPair generateDhKeyPair() throws GeneralSecurityException {
        String algoName;
        if (this.DHGroup.isEC()) {
            algoName = "EC";
        } else {
            algoName = "DiffieHellman";
        }
        this.dhKeyPair = CryptoHelper.generateKeyPair(algoName, this.DHGroup.getAlgorithmParameterSpec());
        return dhKeyPair;
    }

    public PublicKey getPeerPublicKey() {
        return peerPublicKey;
    }

    public PublicKey computePeerPublicKey() throws GeneralSecurityException {
        if (this.peerKeyExchangeData == null) {
            throw new IllegalStateException("No key exchange data for peer; use setPeerKeyExchangeData() first!");
        }
        if (this.DHGroup.isEC()) {
            ECParameterSpec algoSpec = (ECParameterSpec) this.DHGroup.getAlgorithmParameterSpec();
            peerPublicKey = CryptoHelper.createECPublicKeyFromBytes(algoSpec, this.peerKeyExchangeData);
        } else {
            DHParameterSpec algoSpec = (DHParameterSpec) this.DHGroup.getAlgorithmParameterSpec();
            peerPublicKey = CryptoHelper.createModPPublicKeyFromBytes(algoSpec, this.peerKeyExchangeData);
        }
        return this.peerPublicKey;
    }

    public byte[] getDHSecret() {
        return dhSecret;
    }

    public void setDHSecret(byte[] dhSecret) {
        this.dhSecret = dhSecret;
    }

    public byte[] computeDHSecret() throws GeneralSecurityException, IllegalStateException {
        if (dhKeyPair == null) {
            generateDhKeyPair();
        }
        try {
            computePeerPublicKey();
        } catch (IllegalStateException ex) {
            throw new IllegalStateException("No public key for peer; use setPeerPublicKey() or setPeerKeyExchangeData() first!", ex);
        }
        String dhAlgoName;
        if (this.DHGroup.isEC()) {
            dhAlgoName = "ECDH";
        } else {
            dhAlgoName = "DiffieHellman";
        }
        KeyAgreement keyAgreement = KeyAgreement.getInstance(dhAlgoName);
        keyAgreement.init(dhKeyPair.getPrivate());
        keyAgreement.doPhase(peerPublicKey, true);

        this.dhSecret = keyAgreement.generateSecret();
        while (this.dhSecret.length < this.DHGroup.getPublicKeySizeInBytes()) {
            this.dhSecret = CryptoHelper.byteArrayPrepend(this.dhSecret, (byte) 0x00);
        }
        return this.dhSecret;
    }

    public byte[] getInitiatorNonce() {
        if (!isInitiatorNonceChosen) {
            return null;
        }
        return initiatorNonce;
    }

    public void setInitiatorNonce(byte[] initiatorNonce) {
        this.initiatorNonce = initiatorNonce;
        isInitiatorNonceChosen = true;
    }

    public byte[] getResponderNonce() {
        return responderNonce;
    }

    public void setResponderNonce(byte[] responderNonce) {
        this.responderNonce = responderNonce;
    }

    public byte[] getSAOfferBody() {
        return this.securityAssociationOfferBody;
    }

    public void setSAOfferBody(byte[] securityAssociationOfferBody) {
        this.securityAssociationOfferBody = securityAssociationOfferBody;
    }

    public byte[] getKeyExchangeData() {
        return keyExchangeData;
    }

    public void setKeyExchangeData(byte[] keyExchangeData) {
        this.keyExchangeData = keyExchangeData;
    }

    public byte[] generateKeyExchangeData() throws GeneralSecurityException {
        if (dhKeyPair == null) {
            generateDhKeyPair();
        }
        this.keyExchangeData = CryptoHelper.publicKey2Bytes(dhKeyPair.getPublic());
        return this.keyExchangeData;
    }

    public byte[] getPeerKeyExchangeData() {
        return peerKeyExchangeData;
    }

    public void setPeerKeyExchangeData(byte[] peerKeyExchangeData) {
        this.peerKeyExchangeData = peerKeyExchangeData;
    }

    public byte[] getInboundSpi() {
        return inboundSPI.clone();
    }

    public void setInboundSpi(byte[] spi) {
        if (spi.length != 4) {
            throw new IllegalArgumentException("An SPI has to be 4 bytes long!");
        }
        this.inboundSPI = spi.clone();
    }

    public byte[] getOutboundSpi() {
        return outboundSPI.clone();
    }

    public void setOutboundSpi(byte[] spi) {
        if (spi.length != 4) {
            throw new IllegalArgumentException("An SPI has to be 4 bytes long!");
        }
        this.outboundSPI = spi.clone();
    }

    public ProtocolIDEnum getProtocol() {
        return protocol;
    }

    public void setProtocol(ProtocolIDEnum protocol) {
        this.protocol = protocol;
    }

    public byte[] getInboundKeyMaterial() {
        return inboundKeyMaterial.clone();
    }

    public void setInboundKeyMaterial(byte[] inboundKeyMaterial) {
        this.inboundKeyMaterial = inboundKeyMaterial.clone();
    }

    public byte[] getOutboundKeyMaterial() {
        return outboundKeyMaterial.clone();
    }

    public void setOutboundKeyMaterial(byte[] outboundKeyMaterial) {
        this.outboundKeyMaterial = outboundKeyMaterial.clone();
    }
}
