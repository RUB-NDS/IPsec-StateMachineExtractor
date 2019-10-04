/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import java.security.GeneralSecurityException;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public interface EncryptedISAKMPData {

    void decrypt() throws GeneralSecurityException, ISAKMPParsingException;

    void encrypt() throws GeneralSecurityException;
    
    ISAKMPPayload getUnderlyingPayload();

    byte[] getCiphertext();

    boolean isIsInSync();
    
}
