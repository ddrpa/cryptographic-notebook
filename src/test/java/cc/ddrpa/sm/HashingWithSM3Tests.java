package cc.ddrpa.sm;

import com.google.common.io.BaseEncoding;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * GB/T 32905-2016 信息安全技术 SM3 密码杂凑算法
 * https://std.samr.gov.cn/gb/search/gbDetailed?id=71F772D8119BD3A7E05397BE0A0AB82A
 * <p>
 * SM3 密码杂凑算法的输入为长度为 l（l < 2^64）比特的消息 m，经过填充、迭代压缩，生成杂凑值，杂凑值输出长度为 256 比特。
 */
class HashingWithSM3Tests {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String PLAIN_TEXT = "SM3 密码杂凑算法的输入为长度为 l（l < 2^64）比特的消息 m，经过填充、迭代压缩，生成杂凑值，杂凑值输出长度为 256 比特。";

    @Test
    void HashTest() throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SM3");
        byte[] hashed = digest.digest(PLAIN_TEXT.getBytes(StandardCharsets.UTF_8));
        assertEquals(256, hashed.length * 8);
        System.out.println("SM3 Digested: " + BaseEncoding.base16().lowerCase().encode(hashed));
    }

    /**
     * 附录 A 运算示例一
     * 十六进制字符串 616263 运算结果应当为
     * 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0（十六进制表示）
     *
     * @throws NoSuchAlgorithmException
     */
    @Test
    void AppendixATest() throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SM3");
        byte[] hashed = digest.digest(BaseEncoding.base16().decode("616263"));
        assertEquals(
                "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
                BaseEncoding.base16().lowerCase().encode(hashed));
    }
}