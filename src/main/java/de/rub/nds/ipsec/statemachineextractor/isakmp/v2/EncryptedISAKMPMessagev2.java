/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp.v2;

import de.rub.nds.ipsec.statemachineextractor.isakmp.v2.transforms.TransformENCREnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.v2.transforms.TransformINTEGEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.EncryptedISAKMPData;
import de.rub.nds.ipsec.statemachineextractor.isakmp.PayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPParsingException;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class EncryptedISAKMPMessagev2 extends ISAKMPMessagev2 implements EncryptedISAKMPData {

    private final SecretKey ENCRsecretKey;
    private byte[] INTEGsecretKey;
    private final IvParameterSpec IV;
    private Cipher cipherEnc, cipherDec;
    protected boolean isInSync = false;
    protected byte[] ciphertext;
    protected byte[] plaintext;
    private PayloadTypeEnum nextPayload = PayloadTypeEnum.EncryptedAndAuthenticated;
    private final TransformENCREnum mode;
    private final TransformINTEGEnum auth;
    private EncryptedPayload ENCRPayload = new EncryptedPayload();

    public EncryptedISAKMPMessagev2(SecretKey ENCRsecretKey, TransformENCREnum mode, byte[] IV, byte[] INTEGsecretKey, TransformINTEGEnum auth) throws GeneralSecurityException {
        this.ENCRsecretKey = ENCRsecretKey;
        this.INTEGsecretKey = INTEGsecretKey;
        this.mode = mode;
        this.auth = auth;
        this.cipherDec = Cipher.getInstance(mode.cipherJCEName() + '/' + mode.modeOfOperationJCEName() + "/NoPadding");
        this.cipherEnc = Cipher.getInstance(mode.cipherJCEName() + '/' + mode.modeOfOperationJCEName() + "/NoPadding");
        this.IV = new IvParameterSpec(IV);
        this.ENCRPayload.setIV(IV);
    }

    @Override
    public void encrypt() throws GeneralSecurityException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        this.writeBytesOfPayloads(baos);
        try {
            cipherEnc.init(Cipher.ENCRYPT_MODE, ENCRsecretKey, IV);
        } catch (InvalidKeyException ex) {
            // Generate a null key if there is no good key material available
            /**
        	byte[] nullKeyArr;
            if (mode.isFixedKeySize()) {
                nullKeyArr = new byte[mode.getKeySize()];
            } else {
                nullKeyArr = new byte[16]; // 128 bit has good chances to work with the majority of cipher algorithms
            }
            cipherEnc = Cipher.getInstance(cipherEnc.getAlgorithm()); // we need a new object to circumvent a bug in openJDK-8
            cipherEnc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(nullKeyArr, mode.cipherJCEName()), IV);
            **/
        	System.out.println("TEST");
        }
        this.plaintext = baos.toByteArray();
        //padding check
        if (this.plaintext.length % 16 != 0) {
        	this.ENCRPayload.setPadLength((byte)(16 - ((this.plaintext.length % 16) + 1)));
        	this.ENCRPayload.genPadding();
        	byte[] toEncrypt = new byte[plaintext.length + ENCRPayload.getPadLengthINT() + 1];
        	System.arraycopy(plaintext, 0, toEncrypt, 0, plaintext.length);
        	System.arraycopy(ENCRPayload.getPadding(), 0, toEncrypt, plaintext.length, ENCRPayload.getPadding().length);
        	toEncrypt[plaintext.length + ENCRPayload.getPadLengthINT()] = ENCRPayload.getPadLength();
        	this.ciphertext = cipherEnc.doFinal(toEncrypt);
        	ENCRPayload.setEncryptedPayloads(this.ciphertext);
        } else {
            this.ciphertext = cipherEnc.doFinal(this.plaintext);
        	ENCRPayload.setEncryptedPayloads(this.ciphertext);
        }
        this.isInSync = true;
    }

    @Override
    public void decrypt() throws GeneralSecurityException, ISAKMPParsingException {
        if (this.ciphertext.length == 0) {
            throw new IllegalStateException("No ciphertext set!");
        }
        /**
        cipherDec.init(Cipher.DECRYPT_MODE, ENCRsecretKey, IV);
        this.plaintext = cipherDec.doFinal(this.ciphertext);
        ByteArrayInputStream bais = new ByteArrayInputStream(this.plaintext);
        this.payloads.clear();
        PayloadTypeEnum nextPayload = this.getNextPayload();
        while (nextPayload != PayloadTypeEnum.NONE) {
            Class<? extends ISAKMPPayload> payloadType = ISAKMPPayload.getImplementingClass(nextPayload);
            ISAKMPPayload payload;
            try {
                payload = payloadType.getConstructor((Class<?>[]) null).newInstance((Object[]) null);
            } catch (ReflectiveOperationException | SecurityException ex) {
                throw new ISAKMPParsingException(ex);
            }
            payload.fillFromStream(bais);
            nextPayload = payload.getNextPayload();
            this.addPayload(payload);
        }
        this.nextIV = Arrays.copyOfRange(this.ciphertext, this.ciphertext.length - cipherDec.getBlockSize(), this.ciphertext.length);
        this.plaintext = Arrays.copyOf(this.plaintext, super.getLength() - ISAKMP_HEADER_LEN); // remove padding
        this.isInSync = true;
        **/
    }

    @Override
    public boolean isInSync() {
        return isInSync;
    }

    @Override
    public PayloadTypeEnum getNextPayload() {
        if (this.isInSync) {
            this.nextPayload = super.getNextPayload();
        }
        return this.nextPayload;
    }

    public void setNextPayload(PayloadTypeEnum nextPayload) {
        if (this.nextPayload != nextPayload) {
            this.isInSync = false;
        }
        this.nextPayload = nextPayload;
    }

    public byte[] getPlaintext() {
        if (!isInSync) {
            throw new IllegalStateException("Plaintext not up to date. Run encrypt() or decrypt() first!");
        }
        return plaintext.clone();
    }

    @Override
    public byte[] getCiphertext() {
        if (!isInSync) {
            throw new IllegalStateException("Ciphertext not up to date. Run encrypt() first!");
        }
        return ciphertext.clone();
    }

    public void setCiphertext(ByteArrayInputStream bais) {
        this.ciphertext = new byte[bais.available()];
        bais.read(this.ciphertext, 0, this.ciphertext.length);
        this.isInSync = false;
    }

    @Override
    public int getLength() {
        if (!this.isInSync) {
        	try {
    			this.encrypt();
    		} catch (GeneralSecurityException ex) {
    			throw new RuntimeException(ex);
    		}
        }
        return ISAKMP_HEADER_LEN + this.ENCRPayload.getLength();
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
    	if (!this.isInSync) {
    		this.computeINTEGChecksumData();
    	}
    	super.writeBytes(baos);
    }
    
    public void computeINTEGChecksumData() {
    	if (this.ciphertext == null) {
    		try {
    			this.encrypt();
    		} catch (GeneralSecurityException ex) {
    			throw new RuntimeException(ex);
    		}
    	}
    	addPayload(this.ENCRPayload);
    	final String HmacIdentifier = "Hmac" + this.auth.toString();
    	try {
    		Mac checksumData = Mac.getInstance(HmacIdentifier);
        	SecretKeySpec hmacKey = new SecretKeySpec(this.INTEGsecretKey, HmacIdentifier);
            checksumData.init(hmacKey);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            super.writeBytes(baos);
            byte[] predata = checksumData.doFinal(baos.toByteArray());
            byte[] data = new byte[12]; //dymanic legth!!!!
            System.arraycopy(predata, 0, data, 0, data.length);
            this.ENCRPayload.setINTEGChecksumData(data);
    	} catch (GeneralSecurityException ex) {
			throw new RuntimeException(ex);
    	}
        this.isInSync = true;
    }

    public static EncryptedISAKMPMessagev2 fromPlainMessage(ISAKMPMessagev2 msg, SecretKey ENCRsecretKey, TransformENCREnum mode, byte[] IV, byte[] INTEGsecretKey, TransformINTEGEnum auth) throws GeneralSecurityException {
        EncryptedISAKMPMessagev2 enc = new EncryptedISAKMPMessagev2(ENCRsecretKey, mode, IV, INTEGsecretKey, auth);
        enc.setInitiatorCookie(msg.getInitiatorCookie());
        enc.setResponderCookie(msg.getResponderCookie());
        enc.setVersion(msg.getVersion());
        enc.setMessageId(msg.getMessageId());
    	enc.setExchangeType(msg.getExchangeType());
    	enc.setInitiatorFlag(msg.isInitiatorFlag());
    	enc.setVersionFlag(msg.isVersionFlag());
    	enc.setResponseFlag(msg.isResponseFlag());
        msg.getPayloads().forEach((p) -> {
            enc.addPayload(p);
        });
        return enc;
    }

}
