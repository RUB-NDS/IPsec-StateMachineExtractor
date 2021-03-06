/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.util;

import static java.lang.Math.ceil;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class CryptoHelper {

    private CryptoHelper() {
    }

    public static void prepare() {
        UnlimitedStrengthEnabler.enable();
        if (!(Security.getProviders()[0] instanceof BouncyCastleProvider)) {
            BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
            Security.insertProviderAt(bouncyCastleProvider, 1);
        }
    }

    public static KeyPair generateKeyPair(String algoName, AlgorithmParameterSpec algoSpec) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGen;
        keyPairGen = KeyPairGenerator.getInstance(algoName);
        keyPairGen.initialize(algoSpec);
        return keyPairGen.generateKeyPair();
    }

    public static byte[] publicKey2Bytes(PublicKey pubkey) throws InvalidKeyException {
        if (pubkey instanceof DHPublicKey) {
            return dhPublicKey2Bytes((DHPublicKey) pubkey);
        }
        if (pubkey instanceof ECPublicKey) {
            return ecPublicKey2Bytes((ECPublicKey) pubkey);
        }
        throw new InvalidKeyException("Invalid Public Key");
    }

    private static byte[] dhPublicKey2Bytes(DHPublicKey pubkey) {
        int paramLen = (int) (ceil(pubkey.getParams().getP().bitLength() / 8.0));
        byte[] publicKeyBytes = pubkey.getY().toByteArray();
        while (publicKeyBytes.length < paramLen) {
            publicKeyBytes = byteArrayPrepend(publicKeyBytes, (byte) 0x00);
        }
        if (publicKeyBytes.length == paramLen + 1 && publicKeyBytes[0] == 0) {
            return Arrays.copyOfRange(publicKeyBytes, 1, publicKeyBytes.length);
        }
        return publicKeyBytes;
    }

    private static byte[] ecPublicKey2Bytes(ECPublicKey pubkey) {
        int paramLen = (int) (ceil(pubkey.getParams().getOrder().bitLength() / 8.0));
        int pointSize = paramLen * 2;
        byte[] publicKeyBytes = new byte[pointSize];
        ECPoint w = pubkey.getW();
        byte[] wx = w.getAffineX().toByteArray();
        while (wx.length < paramLen) {
            wx = byteArrayPrepend(wx, (byte) 0x00);
        }
        int start = (wx[0] == 0 && wx.length == paramLen + 1) ? 1 : 0;
        System.arraycopy(wx, start, publicKeyBytes, 0, paramLen);
        byte[] wy = w.getAffineY().toByteArray();
        while (wy.length < paramLen) {
            wy = byteArrayPrepend(wy, (byte) 0x00);
        }
        start = (wy[0] == 0 && wy.length == paramLen + 1) ? 1 : 0;
        System.arraycopy(wy, start, publicKeyBytes, paramLen, paramLen);
        return publicKeyBytes;
    }

    public static byte[] byteArrayPrepend(byte[] a, byte b) {
        byte[] na = new byte[a.length + 1];
        na[0] = b;
        System.arraycopy(a, 0, na, 1, a.length);
        return na;
    }

    public static DHPublicKey createModPPublicKeyFromBytes(DHParameterSpec algoSpec, byte[] bytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // if the first bit is set, the BigInteger is negative. Therefore prepend it with a zero byte.
        byte[] bytesPositive = new byte[bytes.length + 1];
        System.arraycopy(bytes, 0, bytesPositive, 1, bytes.length);
        BigInteger y = new BigInteger(bytesPositive);
        DHPublicKeySpec keyspec = new DHPublicKeySpec(y, algoSpec.getP(), algoSpec.getG());
        KeyFactory kf = KeyFactory.getInstance("DiffieHellman");
        return (DHPublicKey) kf.generatePublic(keyspec);
    }

    public static ECPublicKey createECPublicKeyFromBytes(ECParameterSpec algoSpec, byte[] bytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] xBytesPositive = new byte[(bytes.length / 2) + 1];
        byte[] yBytesPositive = new byte[(bytes.length / 2) + 1];
        System.arraycopy(bytes, 0, xBytesPositive, 1, (bytes.length / 2));
        System.arraycopy(bytes, (bytes.length / 2), yBytesPositive, 1, (bytes.length / 2));
        BigInteger x = new BigInteger(xBytesPositive);
        BigInteger y = new BigInteger(yBytesPositive);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(new ECPoint(x, y), algoSpec);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return (ECPublicKey) keyFactory.generatePublic(pubKeySpec);
    }
}
