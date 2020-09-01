/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.HashPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.IKEv1HandshakeSessionSecrets;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ISAKMPMessage;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.PKCS1EncryptedISAKMPPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.IdentificationPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.NoncePayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.SecurityAssociationPayload;
import de.rub.nds.ipsec.statemachineextractor.util.CryptoHelper;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import de.rub.nds.ipsec.statemachineextractor.networking.LoquaciousClientUdpTransportHandler;
import java.io.IOException;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.Before;

/**
 * Integration tests that mock a responder and replay recorded handshakes.
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv1HandshakeIT {

    static {
        CryptoHelper.prepare();
    }

    IKEHandshake handshake;
    HashMap<String, String> msgPairs = new HashMap<>();

    protected static final String CSR2PubPEM = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxWJ9sySuB3FKqYRwTIPC"
            + "08zDntEo0ywCnRWNSY9bknJ2zBU4F1YliiH5//Li9DdR/j/Ls+ipH5M/ZOFrVuZW"
            + "bbkaqcF5aWmy8LcA/IykimzcgfR3wy+gjtxjP4Igjm/NvHVV3/x3x4Zu4bi34X+G"
            + "z+D3dUNLmNvPe2CGshLjc9BwqohjVozbBe5gNqTzZOGxNIH1EOvTRAqYFtaYwffY"
            + "QLU/JAvE3XRCYhk45zoIeJfHs8w9URDIXkcXyMdBMRfGzZFsyNrjvnwQMyvOwbLb"
            + "N4PWepQqGLMbKJ06NsDcQ8QYMFINw2lGekfxukoWWwOBIe8VOOb3HVCXrSuCe0+d"
            + "bwIDAQAB";
    protected static final String CSR1PrivPEM = "MIIEpQIBAAKCAQEA1VnMrbauriqEy+hGC8HvXJRnoIu7lIOERAg7gQXh/4PN1zvN"
            + "vtSKbndOCCBL2eH6U+NYu8wMy9zButuiVALq45HHdnklPuViQTLZK8VO11xOBKZ2"
            + "f8G0RJUtWfWTArFjaKI0t4DXuEXewyEDyYuuz5WKiTSFTNhEoyGKrkWne31nwJiD"
            + "n7oKm/b/UQ55NYDHa/9gVU6CNl+0KRqeuFRFnWpHX+MqpMSN4DNgfDkiDC1Knas5"
            + "QNwvteZMTV6PP1zBMbX2rCa5QoEypy2S8DKLZqsJ12zNvbjmOOpLXblOU6ZlHsxP"
            + "zF2kfhSQrv2E2/B/Mlv3PyPmbuq/4NKAxHrifQIDAQABAoIBAF55xn5CQDYV0/pr"
            + "n+EC/xjTCtR4LBeG6aIqtxbaYQqB9jvSWrifa7GhGSfWDWCthelx6lA2+o+n8Q3q"
            + "xoZHSHZ/joEzAkBI2WqftrWASPprAI1knWLThx07pfqJGZF+tdOWyJtd7ajHH+7u"
            + "hrvQJBf+U3uQi1rNBg/rAXtMku7GeO9HQT8PKLlT4hrRDAMrXySd0mIpHbFMVZdP"
            + "0Uz5d55KlXcddg9R1s4wZ4wUSjaUI8GK4AJ9KavAsnglO0rEkrCUW4U2qMZIkF42"
            + "4bGah8xuVr/SqjwSD+GDCpx0dZOmA2nnzqL36+pRzV88Dp5SA9QDti8wnvZRQGQp"
            + "j1wlra0CgYEA17jXwblWZ13qlwrlZtvKzJslHwVMUNRJYHf5BM6r/G8f/hXzhkRw"
            + "rdezebaDI0/kCKCQowlbY50AeA/350IyD8qiq7ZTOHIuHMNuB47jBfPoQWT1BFRV"
            + "D2Ukmv3xR40gry9Vw/kto483P/aCR0G4iCGmjd+3t8sN/FaNNoBowDsCgYEA/S+d"
            + "QZxJnfaHl29RnYwKjf0iohBHonngtC5qRg9sR2IoNAzOS+JKjxAsFbJilopoclKl"
            + "cfnisYmRVC8T+KQitu6jnZVY3vjESoBQP4o9L/HbASF30A5ul7cfJMY4p75mzzn7"
            + "jCT9ieFKisgMCrosFygSPD6OeAYwvEJMhxc0tKcCgYEAu/oiaHksRZ6dEUk5ZUwZ"
            + "h/mZe1KOkdCqsBlbMUk2rR3YbvyJ3HI/Df1sM59K3rZ7Ktlfr/IzZLYm9nhTuX0B"
            + "Sql03tRd6E32yLGza3qjcUh9Fp72svMZu/SS1Ux7t7HOzVkeD0tO7bualW4lUBqA"
            + "xn8sN2y/FrUmVsDFBL0YiokCgYEA7cKRAtQprdWdb3ByTGj+YGie5WI0Yzfg9FPC"
            + "KRjCriZXasm70TconUCqpZVnT8eaXgGOrIHliKOPfmbXcl9w2ikwLQPa+UjTzMLC"
            + "mWjQHP4ak+1B/ngPExo8fORIv/3lviTNPMZf8eNHhRxncotybCyNM1XrpHrruV7p"
            + "TtNUA3ECgYEAwLrD4dKcotJFcx1DEqU9FOOQVeujgzW8b+cpX8y/Czq1CImFPbqT"
            + "8CwcNhgDHLCa3gOvHWptQeM4iG6aAty1F0dVXS+QGLBFq9HFPBn5Nj0eWjCV6+QZ"
            + "YuuKKgdda6kh4/eFa7Ko9uCSmCJyNouo6l21a3I4LeKfsSuddZK6sio=";

    public IKEv1HandshakeIT() {
        // Aggressive PSK m1 / m2
        msgPairs.put("75cc633d664fd55600000000000000000110040000000000000000f00400003800000001000000010000002c00010001000000240001000080010007800e0080800200028004000280030001800b0001800c70800a000084375427d76a58cf3db4ab3cf2da9dd44dfef6233affc1d34d75c3aec9d93353a29fc3d6ec1fc4c343e49439302cacca1a52d19877a0fa72a1ee023d67015ffc690361606ec24115655228b50d328636f4fce68253d7fbd1eae905cfc6dc93194e147184279556d86ceeeb33a78b612aabdd6590ca4e609cc88906457787f13ff70500000ca3a34f453de42c670000000c010000000a000301",
                "75cc633d664fd5560534fc1813e089e10110040000000000000001400400003800000001000000010000002c00010001000000240101000080010007800e0080800200028004000280030001800b0001800c70800a0000843af9e9bbff0c40ca81e538ccaca7dab906ae2f48f68b3f03e8c81f361b5cf514ef20d46d46b2c513a342dd3ca210dd069ff995c53f363b4e05c5c4534fe566441343333b615d87efa9d55400c44d5b5a02e41872790749df8aff964cf937fc3e349ec31f3b1cab032202389f87784f44ec4878adec2b974bc17156238937133f050000240f03492d4761a688f493d24424e9a7d19f1a64c4cd697dc900862aa1163f06450d00000c010000000a00030a0d00000c09002689dfd6b71208000014afcad71368a1f1c96b8696fc775701000000001891b7a7f96ea7a07c12ae03af0bc32e9f347685bb");
        // Aggressive PSK m3
        msgPairs.put("75cc633d664fd5560534fc1813e089e108100400000000000000003400000018cd7dbe09500affbe969fadb342d021acd65740cf",
                "");
        // Aggressive PSK qm1 / qm2
        msgPairs.put("75cc633d664fd5560534fc1813e089e108102001e582bf040000009c82ec87b994f7ae97adf4eec2e4fd9c14017fd3e954a4d16096b706c1f49e32b24ff178d5f7088b5b40714dfa0dff9c18bceddd1d7ed98c66fa026625c3231b750dc2b26a070ad61767e8bc357ff5e01d405c5eaa6afd52712f3222abba3fb2484d4b571f0e4c8ae5eba1905fd1496e3988469044c6949fda8824c35ba5b4f708",
                "75cc633d664fd5560534fc1813e089e108102001e582bf04000000acfa4cd71d0cd487efb3e7edce0caafcc34f71cd79714cddee45d5c4de9c364ba7763917cc66f4cd7df1fb53b59ec812a5dcff75383f116c67b94a9c5aae8181dfad81a312157c2ccc93344dbfcec169c18f8c9fe66e8c44de5179b2a39c42b5d798a929b03a167caae1f129c6194fabb74143c9ec623720f16de13f20d819cf737be79ac23f2143f5f43bd15109daa2d1");
        // Aggressive PSK qm3
        msgPairs.put("75cc633d664fd5560534fc1813e089e108102001e582bf040000003ccbe867c2849c3ccf5edff6ee8a40c37a35d25439d95103dd2cf4683cfef9f777",
                "");

        // Main PSK m1 / m2
        msgPairs.put("59cedc5dcea558fe00000000000000000110020000000000000000540000003800000001000000010000002c00010001000000240001000080010007800e0080800200028004000280030001800b0001800c7080",
                "59cedc5dcea558fe9e169842364452570110020000000000000000740d00003800000001000000010000002c00010001000000240101000080010007800e0080800200028004000280030001800b0001800c70800d00000c09002689dfd6b71200000014afcad71368a1f1c96b8696fc77570100");
        // Main PSK m3 / m4
        msgPairs.put("59cedc5dcea558fe9e169842364452570410020000000000000000ac0a000084b5fcea14e2593ee937054b98886ca43b00472167db154ff074e158e8b7fcae77ac35cef073698bfe63c99c6dd64ae25a95d55800a845a5db0640d1c3ea5bb8596cb0ffa5d4db0fd01e1875941b14ad4ac492fb5f6381db934664ad8493fe95aab7f1ff8976f329b5ea0f9ede244e906fb419353e878f2fa92ccd533ba33d79ee0000000c32ae9db36e7418a7",
                "59cedc5dcea558fe9e169842364452570410020000000000000000c40a00008424bb23e799283854458c53d6d735ee8c099008c743c89900b312264d3d372e4ff3986d5890d43e5aa7f2c6adb910b302cddcdf773b74921f8ce0376a338a28d7569fb8d4dab85a799cc753bd7d2fd9a65d4e4b016ea9742349c0d8cb6271061e21f5d6af924fddf05fa3a0c83ce7a22074e779c4fee154a728a4c0d6488adbb300000024ce2b9ff5f8519260b6c8f153529bc5a43121e3aa57a3de7d0d63baba86679e57");
        // Main PSK m5 / m6
        msgPairs.put("59cedc5dcea558fe9e1698423644525705100201000000000000004cfabd2d66f56237c7810b25e185b0186559632459fde4ebb654970a62e83cdd47c9201aad89e40e9500d264aeaa968647",
                "59cedc5dcea558fe9e1698423644525705100201000000000000004c56e985c35cd53530527480fcf20a9faa5a3d45465a20f67d48d3e9c55b09b72253d9030fe2f2cf3a3fa1eae37e3fccaa");
        // Main PSK qm1 / qm2
        msgPairs.put("59cedc5dcea558fe9e1698423644525708102001259cf1330000009ce47a7db59b674dbad6139dd85fa848ed708f401a6d3a5f51cb2c7a536f5d66423c8f836ac940ae79ac8de022830196d280c0552a11d68afaceb75855fa45195c35332ffaef8e2bf2d43361b1d6e560927b67651ea2cab184dc27cb20c138e76529b62655bc127f196969fe16cb3229f049b07af51d3bf0c000747cd944c32e12",
                "59cedc5dcea558fe9e1698423644525708102001259cf133000000ac65d4e7d4b983b417b1e567e10fdec60810585f0954817b8192d9501141c458567ac84c42360176d59e7591ac45c4de7dad738657d49bbca9034247f7ab96dac4f43c3d6cccdeeeae62742cb5c79b5a4db4949504f21e96d38a0f75342b421688a1b62b7157ee7a154f2a0a7eef69138db52361827b50a3b62ce53347aee835bcea1a1ef0b1cc04ec7a167ccec3b4cd36");
        // Main PSK qm3
        msgPairs.put("59cedc5dcea558fe9e1698423644525708102001259cf1330000003cf0fa3ae90bfec0179ffa8592af60cf2febe9f682f629e83e497b8644ae726c1c",
                "");

        // Main PKE m1 / m2
        msgPairs.put("11e79c308ebbd71700000000000000000110020000000000000000540000003800000001000000010000002c00010001000000240001000080010007800e0080800200028004000580030004800b0001800c7080",
                "11e79c308ebbd7172ca4eb67438cfda90110020000000000000000540000003800000001000000010000002c01010001000000240101000080010007800e0080800200028004000580030004800b0001800c7080");
        // Main PKE m3 / m4
        msgPairs.put("11e79c308ebbd7172ca4eb67438cfda90410020000000000000002e80a0000c4d80834a1a206a359e404a57acc4be0e38a0c6db735be27af0ffd4ad3326b52a68175cc115fbc25e73909d9ee7502facbb4138794500a9c727d98d56bcb4408520384ad5ea70a9d1f49cdff13bd757943131360882e2e1fd580b8e5fc147617aa215fc641cd80f21ae86c663ed1e8694f537a302e6f4efe56b78533670752661ba948ec053b6681a1fa9b6fa49a79a503b915cc56d10fd56b6cb13d5238ee63ddd0a7101ad9a470dd0410e94a051559ac7430cc0910304f30c62c65e0ef0ba7e905000104665a9218eb9f8eb3703725e73257c7abdbfdf913147419d719f98a811551b38bcb97958ae356b1db28dc12f09c451fe50a8d7b21083c2ef61bcc28e6920f87c836a0b3b6aa1f4161af8bf2bd3224f4229855a794454e678947e44530a5cbb8aad8c7ae0de0fee80fc6ab7aab648803d52afc30c9485aa6dc33b75d15004cc91bfaf9ebb509a45d0d2c5e3ce03f3a3c92ffacbdacb53bcdf2871659abeb1caf4013d9e44aeabbce348352f375b5722ce87efc708770665baba249407a98d29cd1e4e4afffb62b72ae7f6dfa4da65849b950ea56348075e5151168cff2e9e451014e4abf053edebfb39d1ab083adefb3dba1da147914938fe370784bd943899c5800000104467c30bc16916a50eb1590b15b8a9373bca1fe0db7ef22ad761c2101b21f37f941f5b78738b6a1b2b82b80d615df308a55048552bbac4ff5d4388e3ebab9ec0942906944e2fdca0eb41a524ba83e8f071a1f8b1360358a6c6f170adb16e30cff29c098960bf7980ff68aedf41583dc766b382a832fea27d7ec744ca9f1aee731a6e19a3c91b630f42a07b0756211d13ba34eb0fa2f6aee903afd72b005e3907afade66fabd7757ab2075df47c3f41593a1466174e238e094461236cbabd76d71d9028d4d1b365c042dfb80356103530ea3f8b295ddf4a0f7ffef80b1fbd1642ae10b75fc9e8f856add7c0f18bd08607b41f5b8c1d26c45736298c2660c44bf69",
                "11e79c308ebbd7172ca4eb67438cfda9041002000000000000000330050000c44d6ecaebe4b7fa975986ef3d3f8d388ee36db125522746c4dfe46fc9761346864eaa9d06dac26c14b5b09ba747086b838cbb2b61a19d406629718dc715ac5c007252c582d6777a969d8625e41ce3714229eb21718afb28ad0970e6ccdc5418730592782d16bd5b1c4935d106ce44e50e012b04f4985515c4a7e4dcbc42174c214e5b8bfd9afe24760994ee3a78273a8401bbd509200dc7373708b6144a22649fd26664e11ade7c77aaaa83f540046cd624957abf9bfb3228163c0d4577ca75e20a0001041038f5264c034a43e27212bcc09de98d114e0da9cc48557fadfe158459c88114f6598bbc21d7da3a83c75554b4af20013b0f2656f40f8cbf973de66ca508ba211d3b2997edb548c13ef5c703ec0ea42d1d665b7812dc688eef15c1d2a4a5a3aac7244217218112e551866efa2fc99e8ff374e280cfe06123c7bce04b40ee4d3ace40a28b30d94c4bb7b2f0e73fb3c63dcbcb92189a77007cd47503931e105574e63ed539cb59cf7e58caf397d008a6f44c98b16ff38bd213b6e69fbb3549b0e1a1cc470b9e49d15822f8a2711a97ee99eee86ffcbf5ae4101b6b431bc15d9e7c5704a229b25cad6944a944fecacd64cbc4cd1e572c7bcbf0eea60be3bdd9329f0d000104344f0110a60875607a8aa32174cfc927041b6eafae96ab71f41c89e198e7a504e81f061ecc3081a6037ad305fc6643b0f6de34307f50ffc65a3e55bde6f44abbd5d4d058b650a7472a148d84170542600fb078ad6050789b86993606bbe4d373b82f178699cdde87d473b7f55217204a1432536bcf5549f190d0031440a9781c5408d9635a8066f3e3e3646258a49163c3de5d0c8aea1b883b6e4221ee172c2d759d00831fe80e8cfa1fef53effdef82ab46177135cf5b565b49ad52b5c7c8ae2562084fdc19e853c2929aedcd61c732fdf07b73af354ee3dcea9da4efe22ed5aa93f3c4f280aafa3584f8ac190d5e64a1eafd7b63c1eed919dde27c354d46300d00001412f5f28c457168a9702d9fe274cc01000d000014afcad71368a1f1c96b8696fc775701000d000014d9634c7a438dfda970f20bcb0c1ac1c70000000c09002689dfd6b712");
        // Main PKE m5 / m6
        msgPairs.put("11e79c308ebbd7172ca4eb67438cfda908100201000000000000003c0df555de66de25f39d478c3cd255317c921cd654deb2536da810b7010ecfc5ef",
                "11e79c308ebbd7172ca4eb67438cfda908100201000000000000003c73102555db62ef260456cb5495b84d91c72ab84294f57f7f0e472744ebfcd47f");
        // Main PKE qm1 / qm2
        msgPairs.put("11e79c308ebbd7172ca4eb67438cfda90810200145c9ec040000009cfe00a26d42545b611ec65dcc9a51d14b8b5875e61d5d5c563f6dbafbe8f98427711cfc86c359328e1c5c24db797588bd0d7403c9a3ba51f7195b415b40f410a846c5b2f26666327a024b4a6cbfa6df63663988c682bf41fc61753c11052daa11ab1ac35ef4b9f712f7db6da971872c51ee2dc29086422687a220855559997b9e",
                "11e79c308ebbd7172ca4eb67438cfda90810200145c9ec04000000ccf1cd1754384676ecf14d6f07edb4dc5609b026a70c474ed8dbe24d9de9965c03052fd6d9b65098240ad4e39548ccd319664e8357adc68bfd4297c47e0d8f7194c809e1c5819b77448577c743927ed20e67ba3be9f4f30bb2565afb2a6bf6478681bac4992b893f0f8c22a4306b44779663df89a85a8c485ce6173a6988c977996b939d23c74c7da13d24526ea657071a5466b9537352e24cd4eebb70bc61ea79c22cab2de7715395fe448d108fa3de64");
        // Main PKE qm3
        msgPairs.put("11e79c308ebbd7172ca4eb67438cfda90810200145c9ec040000003c35317d8f719beefd2f8a8e1864b573c0ac45077d8189f42db3728710a59ed5a2",
                "");

        // Messages for testMoreThanOneMessageHandshake()
        msgPairs.put("3bc6ed46d2f233aa00000000000000000110020000000000000000540000003800000001000000010000002c00010001000000240001000080010007800e0080800200028004000580030004800b0001800c7080",
                "3bc6ed46d2f233aa5b5fbd354bbd28f60110020000000000000000540000003800000001000000010000002c01010001000000240101000080010007800e0080800200028004000580030004800b0001800c7080");
        msgPairs.put("3bc6ed46d2f233aa5b5fbd354bbd28f60510020000000000000002e804000104428eabd734da66543900fee747990d5be354067da5bf7594355ea424c62727cd8563c0caf8ebba0e57b187fbf36d27a5dc02362cbbbd0ff6f9a7a3700de74c7cd0799bbf06be7446f9b5d4d485cd122c199c21117c041677a9ae2e47374f28fc78ef839e6910664951afa4bd2d1f6333cbb302e4440b33b10aac6f5359f14590b491ea1978edd4d1c2ff0ae212e118190ae1856bb6f6f635d5a22aa31e74aadb0d9bcf27bd5b4d311ad147b5f84949ddc81f84a94b90139589a389c689771977e0b30ed29e6a88ce41d74016d4363d852df589ce707a7a17248a0dbbeb1beddf72ba4f624ad44c75b3ec331d8a48dce89e23359aea45843f9b221d6644290b2e0a0000c41e9ffb9e21917a0107abee6366348f07bfd69b000e3679a22733ca4ddb865f0afba12d984cb691b31af952673486c851e5ae0341c33d4cfcfdb76e4387154d44ec50652d51674a729c2dba8c7bd5fec584893500257a63712106284c3d56470de58644c40be6d9381552c419412576acd58ce05b9d4b4df9422516b95a442cdaf533870c1fa0fbfb4e814c4eecc554239febf4add7ebd3e254d19880ded836883c219724b05933ba2479ba33e16791532dbd905c8f342f6d6a84c3b10d3d3d5400000104a49e8f892c471b86f0744d3164f3b70699f65f00d17470d89860e3f43d033409d37824509c0f46e6f0fef4f3e34fcabbc2de91ec5b50432cda858af91751198d1ea68cb2dc7ff817ac0104b2d704833b3781c68fdb28469a0be397be3f9b9b20bae3a470afe9b94dd6e16671b54da58f22d810327cbe876b75a383678673dd01d950f8cea34a08d60310781d9175e9116d97fcfe84b2e33e69cf5a8284a7a224db1be54292397194c44743cfb7993715403e1264b046a8d4bc71a8443ded6363f4bc6f5da6472935559604eb7af14d0fc99583f1234e43da033e5870b6334e7947ef5d03e268222f52b57daf4a1d138bac8800b56a7aa04ecfbc16b97a72dd7b",
                "3bc6ed46d2f233aa5b5fbd354bbd28f6041002000000000000000330050000c4fa6b0d38bee373146cc4fb218000bec3908d614f31b24235c712ac7dfe8fc8c0cef14f0590e59329053886df63af8802b17d87a4cf900effd68d2cb083311ed08c25d4b4e2b7e75fcd38b039a2a6c274c40c557f07996825618dee2ff9fbcaf09e25c25e429cb109ff29be5b36b0e82ce15a6e881a1ec56c6af230faa851281cba3ac42f70631abc8a377fa2b4d7f6e2082044e093b4f31cca1e97cabb9db6721e0641b3b74f445acc6118b4df71e454d3e68bc867ac2f291a2cd8486a2cbdae0a00010402bd463754a382282479c8719eb596e5bafe71a4f40ec588dba7076d690a8a80157a469d91c914058903ffd5e6cfd567c5172542c3ebd2a8a01aa4777a7a49aeba9bb61cc1602fe460f60c89110c5bb84220a09e43d75f2cbce3bad470a7e51e8b3ff7f6ee1b8216c8deee048fc55ca4a93367671f20e484d6a9b413b8bc2d2b888163aed40c6cd91dc83770b6131d1732f696597b10713913a3c41c77bf95ecc4028c0f38eaf75d5f6c6a1959929c89f93669113e2cc3c4d90320d4f8b313243dad3fdf6364d8d807b4aa9fcc76cf26216feffe9e53bada9c72d35ac43b307d7906dc8ecbca5347ac171fb3120b97b48942a0dc11f20a056bc32046aadbedd90d000104a1ab6d3b941b1927dc2429449d12ad8dafe0466b2dbe1877677da8081de1f9819c2763698c5d84cbbd5fcc405e17190f518e8ea95a217d239a1c44707c6de81463da9d5add500ee4497ecbecc39054a2d95cf4121234e9ca668d1de5a9119b0abac1574f90bd05b0f11b259df20f37dff0ef92525fc3684efe0f07bcb69d8bc8d123bcf2e13f56dae96833e83024f10e9f89f541e33862d9952015ba832360453604b690e69a87adcfc8465148aa1bfdcf1e811879beb4219d4df82e2296cdb090f59b1c95abff5d21b59a34a341f6f58c3ac262b23f5342c999e6c6622314154385bbc02c08cd295419b599d7a837d909a5dc1b04c0bc94d7f8611d098780330d00001412f5f28c457168a9702d9fe274cc01000d000014afcad71368a1f1c96b8696fc775701000d000014ae981a284bbc28f62a5cb1013b814c890000000c09002689dfd6b712");
        // The answer in this pair actually is two messages, first a v1_MM*_HASH message, second a ResponderLifetime-Notification message
        msgPairs.put("3bc6ed46d2f233aa5b5fbd354bbd28f608100201000000000000013caacc659248fa17a22904cd1117bfea71e19f06cd16a517f6dbc6c439598a1ccf04d7343c536a08d6ac2b3deb3dc5467947d12709d5f77a87672fffe6e400ed089ed74b4cbf7851abeb878483c180bc078608926a5fd6fd60f998ca74397e0cd84e9e0a80eb98e08f2286b914a149a05a3af254f2b00062e61516abc3b67e4a7817c611c72d78cf62ef46b3db6b7db160a91634c157905c5e4530b6fcc83be411f241e40bcfcdf51a9ef6f2bea83d03fa19046d83de84faec962988ff91145b818ddcc37770118657efc2f0872a6b419ace4da35c2458a3f15d97c71cd78d6fbc3f8607b43b10bd419de70c6b17c84493ca2b444ab1e122ef0eab96ed797d097bdf53d25558f67d5ba6e5bb1026128420193d2420f83173ae044fd2801e67ee19",
                "3bc6ed46d2f233aa5b5fbd354bbd28f608100201000000000000003cf219b3ac92cdc9572edb7b496981342dc4b2de59f95c56e9803299a256ef017d3bc6ed46d2f233aa5b5fbd354bbd28f608100501fab8520d0000005cc289ff9473464411f9823574b8ed09efde6f24ea99d88962572355df1e10d2cccf37c5341c9e178bb66c6e1e8a51867d5e30a06e67efe28a7ae4d3453c2ba8c8");
    }

    @Before
    public void setUp() throws Exception {
        handshake = new IKEHandshake(0, InetAddress.getLocalHost(), 500);
        handshake.udpTH = new ClientUdpTransportHandlerMock(new byte[]{10, 0, 3, 1});
        byte[] decoded = Base64.getDecoder().decode(CSR1PrivPEM);
        KeySpec spec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        handshake.ltsecrets.setMyPrivateKey(kf.generatePrivate(spec));
        decoded = Base64.getDecoder().decode(CSR2PubPEM);
        spec = new X509EncodedKeySpec(decoded);
        handshake.ltsecrets.setPeerPublicKeyPKE(kf.generatePublic(spec));
    }

    class ClientUdpTransportHandlerMock extends LoquaciousClientUdpTransportHandler {

        byte[] nextResponse;
        byte[] localAddress;

        public ClientUdpTransportHandlerMock(byte[] localAddress) {
            super(0, "localhost", 0);
            this.localAddress = localAddress;
        }

        @Override
        public InetAddress getLocalAddress() throws IOException {
            return InetAddress.getByAddress(localAddress);
        }

        @Override
        public void initialize() throws IOException {
        }

        @Override
        public void closeConnection() throws IOException {
        }

        @Override
        public boolean isInitialized() {
            return true;
        }

        @Override
        public void sendData(byte[] data) throws IOException {
            final String dataHex = DatatypeHelper.byteArrayToHexDump(data).toLowerCase();
            if (!msgPairs.containsKey(dataHex)) {
                nextResponse = null;
                throw new IOException("Unexpected Message: " + dataHex);
            }
            nextResponse = DatatypeHelper.hexDumpToByteArray(msgPairs.get(dataHex));
        }

        @Override
        public byte[] fetchData() throws IOException {
            return nextResponse;
        }
    }

    @Test
    public void testAggressiveModePSKHandshake() throws Exception {
        ISAKMPMessage msg;
        IKEMessage answer;
        SecurityAssociationPayload sa;

        sa = SecurityAssociationPayloadFactory.V1_P1_PSK_AES128_SHA1_G2;
        handshake.adjustCiphersuite(sa);
        IKEv1HandshakeSessionSecrets secrets = handshake.secrets_v1;
        secrets.generateDefaults();

        handshake.ltsecrets.setPreSharedKey("AAAA".getBytes());
        {
            KeySpec spec = new PKCS8EncodedKeySpec(DatatypeHelper.hexDumpToByteArray("3082012102010030819506092A864886F70D01030130818702818100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF0201020481830281801445CC10B6FB0AB024B73A55CE8C8CB8689F5473862B337C176B8D976EB04A14F55269413FDE7F88752CD53AA9A4C8CC1ED8282BE43DB4EF6854AE45ED22CFAC2213666DA6D5E7323A934A19455E9D8E53076D15A1C5C36259989717270E2720AE65F34881F0C8417AFC4C7C984882D9864D3BC14B94C26A23B0B76E1F9D7360"));
            KeyFactory kf = KeyFactory.getInstance("DH");
            PrivateKey privkey = kf.generatePrivate(spec);
            spec = new X509EncodedKeySpec(DatatypeHelper.hexDumpToByteArray("3082011D30819306072A8648CE3E020130818702818100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF02010203818400028180375427D76A58CF3DB4AB3CF2DA9DD44DFEF6233AFFC1D34D75C3AEC9D93353A29FC3D6EC1FC4C343E49439302CACCA1A52D19877A0FA72A1EE023D67015FFC690361606EC24115655228B50D328636F4FCE68253D7FBD1EAE905CFC6DC93194E147184279556D86CEEEB33A78B612AABDD6590CA4E609CC88906457787F13FF7"));
            PublicKey pubkey = kf.generatePublic(spec);
            secrets.getHandshakeSA().setDhKeyPair(new KeyPair(pubkey, privkey));
        }
        secrets.setInitiatorCookie(DatatypeHelper.hexDumpToByteArray("75cc633d664fd556"));
        secrets.getHandshakeSA().setInitiatorNonce(DatatypeHelper.hexDumpToByteArray("a3a34f453de42c67"));

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.Aggressive);
        msg.addPayload(sa);
        msg.addPayload(handshake.prepareIKEv1KeyExchangePayload(new byte[4]));
        msg.addPayload(handshake.prepareIKEv1NoncePayload(new byte[4]));
        msg.addPayload(handshake.prepareIKEv1IdentificationPayload());
        answer = handshake.exchangeMessage(msg);

        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("0534fc1813e089e1"), secrets.getResponderCookie());
        assertFalse(((HashPayload) answer.getPayloads().get(answer.getPayloads().size() - 1)).isCheckFailed());

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.Aggressive);
        msg.addPayload(handshake.preparePhase1HashPayload());
        answer = handshake.exchangeMessage(msg);

        assertNull(answer);

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.QuickMode);
        msg.setEncryptedFlag(true);
        msg.setMessageId(DatatypeHelper.hexDumpToByteArray("e582bf04"));
        handshake.setMostRecentMessageID(msg.getMessageId());
        sa = SecurityAssociationPayloadFactory.getV1_P2_ESP_TUNNEL_AES128_SHA1();
        sa.getProposalPayloads().get(0).setSPI(DatatypeHelper.hexDumpToByteArray("f94d660a"));
        msg.addPayload(sa);
        secrets.getSA(msg.getMessageId()).setInitiatorNonce(DatatypeHelper.hexDumpToByteArray("35496d7f0f01f56f"));
        msg.addPayload(handshake.prepareIKEv1NoncePayload(msg.getMessageId()));
        IdentificationPayload id = new IdentificationPayload();
        id.setIdType(IDTypeEnum.IPV4_ADDR_SUBNET);
        id.setIdentificationData(new byte[8]);
        msg.addPayload(id);
        id = new IdentificationPayload();
        id.setIdType(IDTypeEnum.IPV4_ADDR_SUBNET);
        id.setIdentificationData(new byte[8]);
        msg.addPayload(id);
        handshake.addIKEv1Phase2Hash1Payload(msg);
        answer = handshake.exchangeMessage(msg);

        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("cc23d268"), ((SecurityAssociationPayload) answer.getPayloads().get(1)).getProposalPayloads().get(0).getSPI());
        assertFalse(((HashPayload) answer.getPayloads().get(0)).isCheckFailed());

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.QuickMode);
        msg.setEncryptedFlag(true);
        msg.setMessageId(handshake.getMostRecentMessageID());
        handshake.addIKEv1Phase2Hash3Payload(msg);
        answer = handshake.exchangeMessage(msg);

        assertNull(answer);
    }

    @Test
    public void testMainModePSKHandshake() throws Exception {
        ISAKMPMessage msg;
        IKEMessage answer;
        SecurityAssociationPayload sa;

        sa = SecurityAssociationPayloadFactory.V1_P1_PSK_AES128_SHA1_G2;
        handshake.adjustCiphersuite(sa);
        IKEv1HandshakeSessionSecrets secrets = handshake.secrets_v1;
        secrets.generateDefaults();

        handshake.ltsecrets.setPreSharedKey("AAAA".getBytes());
        secrets.setInitiatorCookie(DatatypeHelper.hexDumpToByteArray("59cedc5dcea558fe"));

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.IdentityProtection);
        msg.addPayload(sa);
        answer = handshake.exchangeMessage(msg);

        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("9e16984236445257"), answer.getResponderCookie());

        secrets.getHandshakeSA().setInitiatorNonce(DatatypeHelper.hexDumpToByteArray("32ae9db36e7418a7"));
        {
            KeySpec spec = new PKCS8EncodedKeySpec(DatatypeHelper.hexDumpToByteArray("3082012102010030819506092A864886F70D01030130818702818100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF0201020481830281806F583CA64176389AE033076D036EA24BBE93F0D66A2C64A5ECA5E8F38A521CC5F040CEE069794C6DCB69165795060D4DF4C6CC7A6C64806DE7FA9852151816151E6099533761316FC040476793CF4C2B3A3BB0A96B324549B8FB6519CE22E6F110FC32EB304A155F703EFFE2D9A7082E910A3F3167F26A5C4A166D1A133CB07F"));
            KeyFactory kf = KeyFactory.getInstance("DH");
            PrivateKey privkey = kf.generatePrivate(spec);
            spec = new X509EncodedKeySpec(DatatypeHelper.hexDumpToByteArray("3082011E30819306072A8648CE3E020130818702818100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF0201020381850002818100B5FCEA14E2593EE937054B98886CA43B00472167DB154FF074E158E8B7FCAE77AC35CEF073698BFE63C99C6DD64AE25A95D55800A845A5DB0640D1C3EA5BB8596CB0FFA5D4DB0FD01E1875941B14AD4AC492FB5F6381DB934664AD8493FE95AAB7F1FF8976F329B5EA0F9EDE244E906FB419353E878F2FA92CCD533BA33D79EE"));
            PublicKey pubkey = kf.generatePublic(spec);
            secrets.getHandshakeSA().setDhKeyPair(new KeyPair(pubkey, privkey));
        }

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.IdentityProtection);
        msg.addPayload(handshake.prepareIKEv1KeyExchangePayload(new byte[4]));
        msg.addPayload(handshake.prepareIKEv1NoncePayload(new byte[4]));
        answer = handshake.exchangeMessage(msg);

        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("ce2b9ff5f8519260b6c8f153529bc5a43121e3aa57a3de7d0d63baba86679e57"), ((NoncePayload) answer.getPayloads().get(answer.getPayloads().size() - 1)).getNonceData());

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.IdentityProtection);
        msg.setEncryptedFlag(true);
        msg.addPayload(handshake.prepareIKEv1IdentificationPayload());
        msg.addPayload(handshake.preparePhase1HashPayload());
        answer = handshake.exchangeMessage(msg);

        assertFalse(((HashPayload) answer.getPayloads().get(answer.getPayloads().size() - 1)).isCheckFailed());

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.QuickMode);
        msg.setEncryptedFlag(true);
        msg.setMessageId(DatatypeHelper.hexDumpToByteArray("259cf133"));
        handshake.setMostRecentMessageID(msg.getMessageId());
        sa = SecurityAssociationPayloadFactory.getV1_P2_ESP_TUNNEL_AES128_SHA1();
        sa.getProposalPayloads().get(0).setSPI(DatatypeHelper.hexDumpToByteArray("b75ad16c"));
        msg.addPayload(sa);
        secrets.getSA(msg.getMessageId()).setInitiatorNonce(DatatypeHelper.hexDumpToByteArray("695346ebcf35ab90"));
        msg.addPayload(handshake.prepareIKEv1NoncePayload(msg.getMessageId()));
        IdentificationPayload id = new IdentificationPayload();
        id.setIdType(IDTypeEnum.IPV4_ADDR_SUBNET);
        id.setIdentificationData(new byte[8]);
        msg.addPayload(id);
        id = new IdentificationPayload();
        id.setIdType(IDTypeEnum.IPV4_ADDR_SUBNET);
        id.setIdentificationData(new byte[8]);
        msg.addPayload(id);
        handshake.addIKEv1Phase2Hash1Payload(msg);
        answer = handshake.exchangeMessage(msg);

        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("c6bf8b4d"), ((SecurityAssociationPayload) answer.getPayloads().get(1)).getProposalPayloads().get(0).getSPI());
        assertFalse(((HashPayload) answer.getPayloads().get(0)).isCheckFailed());

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.QuickMode);
        msg.setEncryptedFlag(true);
        msg.setMessageId(handshake.getMostRecentMessageID());
        handshake.addIKEv1Phase2Hash3Payload(msg);
        answer = handshake.exchangeMessage(msg);

        assertNull(answer);
    }

    @Test
    public void testMainModePKEHandshake() throws Exception {
        ISAKMPMessage msg;
        IKEMessage answer;
        SecurityAssociationPayload sa;

        sa = SecurityAssociationPayloadFactory.V1_P1_PKE_AES128_SHA1_G5;
        handshake.adjustCiphersuite(sa);
        IKEv1HandshakeSessionSecrets secrets = handshake.secrets_v1;
        secrets.generateDefaults();

        secrets.setInitiatorCookie(DatatypeHelper.hexDumpToByteArray("11e79c308ebbd717"));

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.IdentityProtection);
        msg.addPayload(sa);
        answer = handshake.exchangeMessage(msg);

        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("2ca4eb67438cfda9"), answer.getResponderCookie());

        secrets.getHandshakeSA().setInitiatorNonce(DatatypeHelper.hexDumpToByteArray("BA4994B250A8D49F"));
        {
            KeySpec spec = new PKCS8EncodedKeySpec(DatatypeHelper.hexDumpToByteArray("308201A20201003081D506092A864886F70D0103013081C70281C100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF0201020481C40281C100DF80749B2B68E33C17F3D8FDE49610D0552CA742A5C259C9917C438EED3A5F0F0EB090F1D2B6B1D85B1C4A56AEA92CD5636D5F26FB7F7A931B5D4827B8D1D30E59FE2FEAD91AFA3F668EE2336808CB008B11A1E22705683B444B4F64C6F6E2D725CCB204AA4B59DFFB9A1647222F7D4D586C0873A051C675FC3170D26F4C051AB976626F5AA9D76A12E727FCFB75CF0C02D06A90475B5A553C8A1DB196AFFDF8579E874ABABE9A83A7FA23B0676C103EA31AB6D34C97603A305E281DDC021E61"));
            KeyFactory kf = KeyFactory.getInstance("DH");
            PrivateKey privkey = kf.generatePrivate(spec);
            spec = new X509EncodedKeySpec(DatatypeHelper.hexDumpToByteArray("3082019E3081D306072A8648CE3E02013081C70281C100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF0201020381C5000281C100D80834A1A206A359E404A57ACC4BE0E38A0C6DB735BE27AF0FFD4AD3326B52A68175CC115FBC25E73909D9EE7502FACBB4138794500A9C727D98D56BCB4408520384AD5EA70A9D1F49CDFF13BD757943131360882E2E1FD580B8E5FC147617AA215FC641CD80F21AE86C663ED1E8694F537A302E6F4EFE56B78533670752661BA948EC053B6681A1FA9B6FA49A79A503B915CC56D10FD56B6CB13D5238EE63DDD0A7101AD9A470DD0410E94A051559AC7430CC0910304F30C62C65E0EF0BA7E9"));
            PublicKey pubkey = kf.generatePublic(spec);
            secrets.getHandshakeSA().setDhKeyPair(new KeyPair(pubkey, privkey));
        }

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.IdentityProtection);
        msg.addPayload(handshake.prepareIKEv1KeyExchangePayload(new byte[4]));
        PKCS1EncryptedISAKMPPayload noncePayload = (PKCS1EncryptedISAKMPPayload) handshake.prepareIKEv1NoncePayload(new byte[4]);
        noncePayload.encrypt();
        Field encryptedBodyField = noncePayload.getClass().getDeclaredField("encryptedBody");
        encryptedBodyField.setAccessible(true);
        encryptedBodyField.set(noncePayload, DatatypeHelper.hexDumpToByteArray("665a9218eb9f8eb3703725e73257c7abdbfdf913147419d719f98a811551b38bcb97958ae356b1db28dc12f09c451fe50a8d7b21083c2ef61bcc28e6920f87c836a0b3b6aa1f4161af8bf2bd3224f4229855a794454e678947e44530a5cbb8aad8c7ae0de0fee80fc6ab7aab648803d52afc30c9485aa6dc33b75d15004cc91bfaf9ebb509a45d0d2c5e3ce03f3a3c92ffacbdacb53bcdf2871659abeb1caf4013d9e44aeabbce348352f375b5722ce87efc708770665baba249407a98d29cd1e4e4afffb62b72ae7f6dfa4da65849b950ea56348075e5151168cff2e9e451014e4abf053edebfb39d1ab083adefb3dba1da147914938fe370784bd943899c58"));
        msg.addPayload(noncePayload);
        PKCS1EncryptedISAKMPPayload identificationPayload = (PKCS1EncryptedISAKMPPayload) handshake.prepareIKEv1IdentificationPayload();
        identificationPayload.encrypt();
        encryptedBodyField.set(identificationPayload, DatatypeHelper.hexDumpToByteArray("467c30bc16916a50eb1590b15b8a9373bca1fe0db7ef22ad761c2101b21f37f941f5b78738b6a1b2b82b80d615df308a55048552bbac4ff5d4388e3ebab9ec0942906944e2fdca0eb41a524ba83e8f071a1f8b1360358a6c6f170adb16e30cff29c098960bf7980ff68aedf41583dc766b382a832fea27d7ec744ca9f1aee731a6e19a3c91b630f42a07b0756211d13ba34eb0fa2f6aee903afd72b005e3907afade66fabd7757ab2075df47c3f41593a1466174e238e094461236cbabd76d71d9028d4d1b365c042dfb80356103530ea3f8b295ddf4a0f7ffef80b1fbd1642ae10b75fc9e8f856add7c0f18bd08607b41f5b8c1d26c45736298c2660c44bf69"));
        msg.addPayload(identificationPayload);
        answer = handshake.exchangeMessage(msg);

        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("A94233221932229B8DB685D5A8B518307429A276"), ((NoncePayload) (((PKCS1EncryptedISAKMPPayload) answer.getPayloads().get(2)).getUnderlyingPayload())).getNonceData());

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.IdentityProtection);
        msg.setEncryptedFlag(true);
        msg.addPayload(handshake.preparePhase1HashPayload());
        answer = handshake.exchangeMessage(msg);

        assertFalse(((HashPayload) answer.getPayloads().get(answer.getPayloads().size() - 1)).isCheckFailed());

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.QuickMode);
        msg.setEncryptedFlag(true);
        msg.setMessageId(DatatypeHelper.hexDumpToByteArray("45c9ec04"));
        handshake.setMostRecentMessageID(msg.getMessageId());
        sa = SecurityAssociationPayloadFactory.getV1_P2_ESP_TUNNEL_AES128_SHA1();
        sa.getProposalPayloads().get(0).setSPI(DatatypeHelper.hexDumpToByteArray("ac8eca3c"));
        msg.addPayload(sa);
        secrets.getSA(msg.getMessageId()).setInitiatorNonce(DatatypeHelper.hexDumpToByteArray("508d6b24469f8136"));
        msg.addPayload(handshake.prepareIKEv1NoncePayload(msg.getMessageId()));
        IdentificationPayload id = new IdentificationPayload();
        id.setIdType(IDTypeEnum.IPV4_ADDR_SUBNET);
        id.setIdentificationData(DatatypeHelper.hexDumpToByteArray("0a000100ffffff00"));
        msg.addPayload(id);
        id = new IdentificationPayload();
        id.setIdType(IDTypeEnum.IPV4_ADDR_SUBNET);
        id.setIdentificationData(DatatypeHelper.hexDumpToByteArray("0a000200ffffff00"));
        msg.addPayload(id);
        handshake.addIKEv1Phase2Hash1Payload(msg);
        answer = handshake.exchangeMessage(msg);

        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("4589f1f1"), ((SecurityAssociationPayload) answer.getPayloads().get(1)).getProposalPayloads().get(0).getSPI());
        assertFalse(((HashPayload) answer.getPayloads().get(0)).isCheckFailed());

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.QuickMode);
        msg.setEncryptedFlag(true);
        msg.setMessageId(handshake.getMostRecentMessageID());
        handshake.addIKEv1Phase2Hash3Payload(msg);
        answer = handshake.exchangeMessage(msg);

        assertNull(answer);
    }

    @Test
    public void testMoreThanOneMessageHandshake() throws Exception {
        ISAKMPMessage msg;
        IKEMessage answer;
        SecurityAssociationPayload sa;

        handshake.udpTH = new ClientUdpTransportHandlerMock(new byte[]{10, 14, 0, 1});
        sa = SecurityAssociationPayloadFactory.V1_P1_PKE_AES128_SHA1_G5;
        handshake.adjustCiphersuite(sa);
        IKEv1HandshakeSessionSecrets secrets = handshake.secrets_v1;
        secrets.generateDefaults();

        secrets.setInitiatorCookie(DatatypeHelper.hexDumpToByteArray("3bc6ed46d2f233aa"));

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.IdentityProtection);
        msg.addPayload(sa);
        answer = handshake.exchangeMessage(msg);

        secrets.getHandshakeSA().setInitiatorNonce(DatatypeHelper.hexDumpToByteArray("AFACCCE973091E11D016F24B36F2DD0E"));
        {
            KeySpec spec = new PKCS8EncodedKeySpec(DatatypeHelper.hexDumpToByteArray("308201A20201003081D506092A864886F70D0103013081C70281C100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF0201020481C40281C100908FD0B55106476164715EBCDF5CA41E89C14CCEC26EF15CB93F4C778B7E822AA7AFB5AB044F23B2F2795B9E133D315069D4D8FDFCE26745D657C9BEAB090B1EEA0B92961DBB3C9CBC54A839D0B369F4C83D711A96A2300954881983A2B0F954B8FF0885E9E8B0B0CC69160D4524C6CED78048F92122F747B36F5C5337CDD7E2F66020497053D78896F61BFA924626114DB214B2489843DB8372DB29D0713D4F56A4708FCA95347F6E38401E12B8BBEEEE2E496CE09CD3E36A9750E0CFFAA948"));
            KeyFactory kf = KeyFactory.getInstance("DH");
            PrivateKey privkey = kf.generatePrivate(spec);
            spec = new X509EncodedKeySpec(DatatypeHelper.hexDumpToByteArray("3082019D3081D306072A8648CE3E02013081C70281C100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF0201020381C4000281C01E9FFB9E21917A0107ABEE6366348F07BFD69B000E3679A22733CA4DDB865F0AFBA12D984CB691B31AF952673486C851E5AE0341C33D4CFCFDB76E4387154D44EC50652D51674A729C2DBA8C7BD5FEC584893500257A63712106284C3D56470DE58644C40BE6D9381552C419412576ACD58CE05B9D4B4DF9422516B95A442CDAF533870C1FA0FBFB4E814C4EECC554239FEBF4ADD7EBD3E254D19880DED836883C219724B05933BA2479BA33E16791532DBD905C8F342F6D6A84C3B10D3D3D54"));
            PublicKey pubkey = kf.generatePublic(spec);
            secrets.getHandshakeSA().setDhKeyPair(new KeyPair(pubkey, privkey));
        }

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.IdentityProtection);
        PKCS1EncryptedISAKMPPayload identificationPayload = (PKCS1EncryptedISAKMPPayload) handshake.prepareIKEv1IdentificationPayload();
        identificationPayload.encrypt();
        Field encryptedBodyField = identificationPayload.getClass().getDeclaredField("encryptedBody");
        encryptedBodyField.setAccessible(true);
        encryptedBodyField.set(identificationPayload, DatatypeHelper.hexDumpToByteArray("428eabd734da66543900fee747990d5be354067da5bf7594355ea424c62727cd8563c0caf8ebba0e57b187fbf36d27a5dc02362cbbbd0ff6f9a7a3700de74c7cd0799bbf06be7446f9b5d4d485cd122c199c21117c041677a9ae2e47374f28fc78ef839e6910664951afa4bd2d1f6333cbb302e4440b33b10aac6f5359f14590b491ea1978edd4d1c2ff0ae212e118190ae1856bb6f6f635d5a22aa31e74aadb0d9bcf27bd5b4d311ad147b5f84949ddc81f84a94b90139589a389c689771977e0b30ed29e6a88ce41d74016d4363d852df589ce707a7a17248a0dbbeb1beddf72ba4f624ad44c75b3ec331d8a48dce89e23359aea45843f9b221d6644290b2e"));
        msg.addPayload(identificationPayload);
        msg.addPayload(handshake.prepareIKEv1KeyExchangePayload(new byte[4]));
        PKCS1EncryptedISAKMPPayload noncePayload = (PKCS1EncryptedISAKMPPayload) handshake.prepareIKEv1NoncePayload(new byte[4]);
        noncePayload.encrypt();
        encryptedBodyField = noncePayload.getClass().getDeclaredField("encryptedBody");
        encryptedBodyField.setAccessible(true);
        encryptedBodyField.set(noncePayload, DatatypeHelper.hexDumpToByteArray("a49e8f892c471b86f0744d3164f3b70699f65f00d17470d89860e3f43d033409d37824509c0f46e6f0fef4f3e34fcabbc2de91ec5b50432cda858af91751198d1ea68cb2dc7ff817ac0104b2d704833b3781c68fdb28469a0be397be3f9b9b20bae3a470afe9b94dd6e16671b54da58f22d810327cbe876b75a383678673dd01d950f8cea34a08d60310781d9175e9116d97fcfe84b2e33e69cf5a8284a7a224db1be54292397194c44743cfb7993715403e1264b046a8d4bc71a8443ded6363f4bc6f5da6472935559604eb7af14d0fc99583f1234e43da033e5870b6334e7947ef5d03e268222f52b57daf4a1d138bac8800b56a7aa04ecfbc16b97a72dd7b"));
        msg.addPayload(noncePayload);

        answer = handshake.exchangeMessage(msg);

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.IdentityProtection);
        msg.setEncryptedFlag(true);
        msg.addPayload(handshake.preparePhase1HashPayload());
        identificationPayload = (PKCS1EncryptedISAKMPPayload) handshake.prepareIKEv1IdentificationPayload();
        identificationPayload.encrypt();
        encryptedBodyField = identificationPayload.getClass().getDeclaredField("encryptedBody");
        encryptedBodyField.setAccessible(true);
        encryptedBodyField.set(identificationPayload, DatatypeHelper.hexDumpToByteArray("b80c23042f1ba728e14f15d4988ced90c0461c14c137c8a9b193601822af1ea98ffab1b37715a2d7c2cb3b9a6c9710659141f2ddaf59cb22d8e7a91496914a2d2b55566d27e12970187ca64e0d52117fc8a715877c2808b56ec6a47f0073eac77652797c58ff9981fc7cda928c12716f8982009af953e50f456ab67e425de1731ed03254ae375096e41657a89e2ae7429640054d79fb596456e0ddd9ecf767e48e807cbdd59feb0955eee94a88dafe87ad4e582a6bcde03c550cbe1fdad9c8895ab8d172a57c6b3f324cd76db8615a877ffc573ec648d284b6bb5af32d76d8b9fc239be547fd1e7d3a5848e580a378231b6e15d4a67a42640e20b0c87d13232c"));
        msg.addPayload(identificationPayload);
        answer = handshake.exchangeMessage(msg);
    }
}
