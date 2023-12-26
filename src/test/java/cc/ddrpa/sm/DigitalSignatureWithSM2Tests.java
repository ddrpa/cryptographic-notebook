package cc.ddrpa.sm;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertTrue;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class DigitalSignatureWithSM2Tests {
    static {
        if (null == Security.getProvider("BC")) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static final String DEFAULT_CURVE = "sm2p256v1";
    private static final String PLAIN_TEXT = "SM2椭圆曲线公钥密码算法（以下简称 SM2）是由 GB/T 32918 给出的一组非对称算法，其中包括 SM2-1 椭圆曲线数字签名算法，SM2-2 椭圆曲线密钥协商协议、SM2-3 椭圆曲线加密算法。";

    static String privateKeyAsString = "";
    static String publicKeyAsString = "";
    static String signatureAsString = "";

    @Test
    @Order(1)
    void generateKeyPairTest() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        // SM2 推荐椭圆曲线
        X9ECParameters x9ECParameters = GMNamedCurves.getByName(DEFAULT_CURVE);
        // 设置曲线方程
        ECParameterSpec ecParameterSpec = new ECParameterSpec(x9ECParameters.getCurve(),
                x9ECParameters.getG(),
                x9ECParameters.getN(),
                x9ECParameters.getH());
        keyPairGenerator.initialize(ecParameterSpec, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        BCECPrivateKey privateKey = (BCECPrivateKey) keyPair.getPrivate();
        BCECPublicKey publicKey = (BCECPublicKey) keyPair.getPublic();

        // 私钥可以表达为大整数
        // 也可保存为 16 进制字符串
        privateKeyAsString = privateKey.getD().toString(16);
        System.out.println("Private Key: " + privateKeyAsString);
        // 保存公钥，公钥本身是 X509 格式，可以直接保存为字符串
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        X509EncodedKeySpec keySpec = keyFactory.getKeySpec(publicKey, X509EncodedKeySpec.class);
        assertTrue(Arrays.equals(keySpec.getEncoded(), publicKey.getEncoded()));
        System.out.println("Public Key(toString): " + publicKey);
        System.out.println("Public Key(Q.encode): " + Base64.getEncoder().encodeToString(publicKey.getQ().getEncoded(true)));
        publicKeyAsString = Base64.getEncoder().encodeToString(publicKey.getQ().getEncoded(true));
    }

    @Test
    @Order(2)
    void signTest() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        // 获取私钥对象 D
        BigInteger d = new BigInteger(privateKeyAsString, 16);
        // SM2 推荐椭圆曲线
        X9ECParameters x9ECParameters = GMNamedCurves.getByName(DEFAULT_CURVE);
        // 设置曲线方程
        ECParameterSpec ecParameterSpec = new ECParameterSpec(x9ECParameters.getCurve(),
                x9ECParameters.getG(),
                x9ECParameters.getN(),
                x9ECParameters.getH());
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        BCECPrivateKey privateKey = (BCECPrivateKey) keyFactory.generatePrivate(new ECPrivateKeySpec(d, ecParameterSpec));
        Signature signature = Signature.getInstance(GMObjectIdentifiers.sm2sign_with_sm3.toString(), "BC");
        signature.initSign(privateKey);
        signature.update(PLAIN_TEXT.getBytes(StandardCharsets.UTF_8));
        byte[] signed = signature.sign();
        signatureAsString = Base64.getEncoder().encodeToString(signed);
        System.out.println("Signed(Base64): " + Base64.getEncoder().encodeToString(signed));
    }

    @Test
    @Order(3)
    void verifyTest() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, InvalidKeySpecException {
        // SM2 推荐椭圆曲线
        X9ECParameters x9ECParameters = GMNamedCurves.getByName(DEFAULT_CURVE);
        // 设置曲线方程
        ECParameterSpec ecParameterSpec = new ECParameterSpec(x9ECParameters.getCurve(),
                x9ECParameters.getG(),
                x9ECParameters.getN(),
                x9ECParameters.getH());
        Signature signature = Signature.getInstance(GMObjectIdentifiers.sm2sign_with_sm3.toString(), "BC");
        ECPoint ecPoint = x9ECParameters.getCurve().decodePoint(Base64.getDecoder().decode(publicKeyAsString));
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        BCECPublicKey key = (BCECPublicKey) keyFactory.generatePublic(new ECPublicKeySpec(ecPoint, ecParameterSpec));
//                new ECPublicKeySpec(ecPoint, ecParameterSpec));
        // 初始化为验签状态
        signature.initVerify(key);
        signature.update(PLAIN_TEXT.getBytes(StandardCharsets.UTF_8));
        assertTrue(signature.verify(Base64.getDecoder().decode(signatureAsString)));
    }
}