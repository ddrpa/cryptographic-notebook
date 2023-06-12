package cc.ddrpa;

import com.google.common.io.BaseEncoding;
import com.google.common.primitives.Longs;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

class TOTPTests {
    /**
     * 参考 Google Authenticator 的代码
     * https://github.com/google/google-authenticator-libpam/blob/master/src/google-authenticator.c
     * 密码是 16 个字符，且只能使用 Base32 范围内的字符（大写字母 A-Z 和 2-7）
     * 可以用于生成二维码或手动录入
     *
     * @return
     */
    private String generateSecret() {
        SecureRandom random = new SecureRandom();
        byte[] buffer = new byte[10];
        random.nextBytes(buffer);
        return BaseEncoding.base32().encode(buffer);
    }

    private String calculateOTPCode(String secret, byte[] time) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] key = BaseEncoding.base32().decode(secret);
        Mac hmac = Mac.getInstance("HmacSHA1");
        hmac.init(new SecretKeySpec(key, "HmacSHA1"));
        byte[] hash = hmac.doFinal(time);
        int offset = hash[20 - 1] & 0xF;
        // We're using a long because Java hasn't got unsigned int.
        long truncatedHash = 0;
        for (int i = 0; i < 4; ++i) {
            truncatedHash <<= 8;
            // We are dealing with signed bytes:
            // we just keep the first byte.
            truncatedHash |= (hash[offset + i] & 0xFF);
        }
        truncatedHash &= 0x7FFFFFFF;
        truncatedHash %= 1000000;
        return String.valueOf((int) truncatedHash);
    }

    /**
     * 使用 URI 生成注册二维码，然后用任意两步验证器扫描注册
     */
    @Test
    void generateRegisterQRCode() {
        String secret = generateSecret();
        String issuer = "DDRPA";
        String account = "yufan@live.com";
        String qrcode = String.format("otpauth://totp/%s:%s?secret=%s", issuer, account, secret);
        System.out.println(qrcode);
    }

    /**
     * 替换为自己的密钥，然后验证
     *
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    @Test
    void verify() throws NoSuchAlgorithmException, InvalidKeyException {
        long time = (System.currentTimeMillis() / 1000L) / 30L;
        System.out.println(calculateOTPCode("U73ESF52R37QYRPW", Longs.toByteArray(time)));
    }
}