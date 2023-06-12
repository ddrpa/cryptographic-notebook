# 实用现代密码学参考代码（Working in Progress）

搭配 [实用现代密码学（WIP）](https://yufanonsoftware.me/posts/essential-cryptography-for-developers.html) 食用。
你也可以访问[本站的大陆镜像](https://yufanonsoftware.cc/posts/essential-cryptography-for-developers.html) ，不过我的 CDN 策略没配好，更新会有延迟。

## 使用 Google Tink

### 使用 Tinkey 工具管理密钥集

注意：接下来的示例中关于密钥集的操作产生的都是明文密钥集，在生产环节中至少使用 `podman secret` 保护这个秘密。

创建 AEAD 方案密钥集

```shell
tinkey create-keyset --key-template AES128_GCM --out src/test/resources/tinkey-keyset-aead.json
```

由于这里指定了 `AES128_GCM`，接下来往密钥集添加的密钥都必须属于 AEAD Primitive，也就是说必须为 `AES-GCM`, `AES-GCM-SIV`, `AES-CTR-HMAC`, `AES-EAX`, `KMS Envelope`, 
`CHACHA20-POLY1305`, `XCHACHA20-POLY1305` 当中的一种

```shell
# 向已有密钥集中添加密钥，生成新的密钥集文件
tinkey add-key --in src/test/resources/tinkey-keyset-aead.json --key-template CHACHA20_POLY1305 --out src/test/resources/tinkey-keyset-aead-new.json
# 不要贸然使用该命令，至少做好备份
rm -f src/test/resources/tinkey-keyset-aead.json
mv src/test/resources/tinkey-keyset-aead-new.json src/test/resources/tinkey-keyset-aead.json
```

## 创建其他密钥集

加密大量数据时使用流式 AEAD 方案：

```shell
tinkey create-keyset --key-template AES128_GCM_HKDF_1MB --out src/test/resources/tinkey-keyset-streaming-aead.json
```

生成消息认证使用的密钥集

```shell
tinkey create-keyset --key-template HMAC_SHA256_128BITTAG --out src/test/resources/tinkey-keyset-mac.json
```

交换数据时使用 DHKEM+AES 混合方案，先生成私钥密钥集，再根据私钥密钥集生成公钥密钥集：

```shell
tinkey create-keyset --key-template DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_128_GCM --out src/test/resources/tinkey-keyset-data-exchange-private.json
tinkey create-public-keyset --in src/test/resources/tinkey-keyset-data-exchange-private.json --out src/test/resources/tinkey-keyset-data-exchange-public.json
```

生成数字签名使用的密钥集

```shell
tinkey create-keyset --key-template ECDSA_P256 --out src/test/resources/tinkey-keyset-signature-private.json
tinkey create-public-keyset --in src/test/resources/tinkey-keyset-signature-private.json --out src/test/resources/tinkey-keyset-signature-public.json
```
