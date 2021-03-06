/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike;

import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public abstract class GenericIKEHandshakeSessionSecrets {

    protected static final int KEY_MATERIAL_AMOUNT = 512;
    private boolean isInitiatorCookieChosen = false;
    protected byte[] initiatorCookie = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    protected byte[] responderCookie = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    protected final Map<String, byte[]> IVs = new HashMap<>();
    protected final Map<String, SecurityAssociationSecrets> SAs = new HashMap<>();
    protected SecurityAssociationSecrets HandshakeSA;
    private final GenericIKECiphersuite ciphersuite;
    protected final HandshakeLongtermSecrets ltsecrets;

    public GenericIKEHandshakeSessionSecrets(GenericIKECiphersuite ciphersuite, HandshakeLongtermSecrets ltsecrets) {
        this.ciphersuite = ciphersuite;
        this.ltsecrets = ltsecrets;
    }

    public SecurityAssociationSecrets getHandshakeSA() {
        return HandshakeSA;
    }

    public final void updateHandshakeSA() {
        if (this.HandshakeSA == null || this.ciphersuite.getDhGroup() != this.HandshakeSA.getDHGroup()) {
            this.HandshakeSA = new SecurityAssociationSecrets(this.ciphersuite.getDhGroup());
            this.SAs.put("00000000", this.HandshakeSA);
        }
    }
    
    public void generateDefaults() throws GeneralSecurityException {
        updateHandshakeSA();
        this.HandshakeSA.generateDhKeyPair();
    }

    public byte[] getInitiatorCookie() {
        if (!isInitiatorCookieChosen) {
            return null;
        }
        return initiatorCookie;
    }

    public void setInitiatorCookie(byte[] initiatorCookie) {
        this.initiatorCookie = initiatorCookie;
        isInitiatorCookieChosen = true;
    }

    public byte[] getResponderCookie() {
        return responderCookie;
    }

    public void setResponderCookie(byte[] responderCookie) {
        this.responderCookie = responderCookie;
    }

    public abstract void computeSecretKeys() throws GeneralSecurityException;

    public abstract void computeKeyMaterial(SecurityAssociationSecrets sas) throws GeneralSecurityException;

    public final SecurityAssociationSecrets getSA(byte[] msgID) {
        String msgIDStr = DatatypeHelper.byteArrayToHexDump(msgID);
        if (!SAs.containsKey(msgIDStr)) {
            SAs.put(msgIDStr, new SecurityAssociationSecrets(HandshakeSA.getDHGroup())); //TODO: Set group based on Security Association payload
        }
        return SAs.get(msgIDStr);
    }

    public abstract byte[] getIV(byte[] msgID) throws GeneralSecurityException;
    
    public void setIV(byte[] msgID, byte[] iv) {
        String msgIDStr = DatatypeHelper.byteArrayToHexDump(msgID);
        this.IVs.put(msgIDStr, iv);
    }

}
