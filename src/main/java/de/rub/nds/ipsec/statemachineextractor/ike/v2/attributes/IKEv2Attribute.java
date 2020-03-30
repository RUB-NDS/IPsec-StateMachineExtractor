/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v2.attributes;

import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPAttribute;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.IKEv2Ciphersuite;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public interface IKEv2Attribute extends ISAKMPAttribute {

    public void configureCiphersuite(IKEv2Ciphersuite ciphersuite);

}
