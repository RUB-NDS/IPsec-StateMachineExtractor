/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp;

import de.rub.nds.ipsec.statemachineextractor.FixedLengthByteStreamSerializable;

/**
 * A marker interface for all objects that form datastructures of ISAKMP.
 * 
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public interface ISAKMPSerializable extends FixedLengthByteStreamSerializable {

}
