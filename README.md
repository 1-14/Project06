# Project06

## Range Proofs from Hash Functions简介

![image](https://github.com/1-14/Project06/blob/main/1.png)

"Range Proofs from Hash Functions" 是一个用于验证数值范围的方案，旨在确保一个数字位于特定的区间内，同时不泄露具体的数值。这个方案通常与加密货币和区块链技术有关，特别是与保护隐私相关的场景中使用。

在加密货币的交易中，为了确保交易的有效性和安全性，需要验证交易中涉及的数值是否满足特定条件。例如，确保交易的金额在可接受的范围内，或者确保交易中所使用的数字满足一定的条件。然而，在验证这些条件时，不能直接公开数值，因为这可能会泄露用户的隐私。

Range Proofs 的目标是解决这个问题，它允许用户对数值的范围进行证明，而无需泄露确切的数值。它通常基于哈希函数的性质，该函数能够将数据转换为独特的、看似随机的哈希值。

HashWires相关参考链接：

https://zkproof.org/2021/05/05/hashwires-range-proofs-from-hash-functions/

https://www.researchgate.net/publication/353438246_HashWires_Hyperefficient_Credential-Based_Range_Proofs

https://github.com/novifinancial/hashwires

## 原理

![image](https://github.com/1-14/Project06/blob/main/2.png)

原文链接：https://zkproof.org/2021/05/05/hashwires-range-proofs-from-hash-functions/

## 关键代码及解释

### Issuer

使用 SHA-256 哈希函数和 RSA 签名算法,选择随机数种子，并计算其hash值s，然后计算k，并对c做k重hash。最后对c签名并发送给Alice(s, sig_c)。

```
public class Issuer {
    public Issuer(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }
    public String[] setup() {
        SHA256 sha256 = new SHA256();

        seed = genRandom();
        s = sha256.hash(seed);
        k = 2100 - 1978;

        c = s;
        for (int i = 0; i < k; i++)
            c = sha256.hash(c);
        sig_c = Sign_RSA.sign(privateKey, c);

        return new String[]{s, sig_c};
    }

    private String genRandom() {
        SecureRandom random = new SecureRandom();
        byte[] randomBytes = new byte[16];

        random.nextBytes(randomBytes);

        StringBuilder sb = new StringBuilder();
        for (byte b : randomBytes)
            sb.append(String.format("%02x", b));

        return sb.toString();
    }

    public int k;
    public String seed, c, s, sig_c;
    private PrivateKey privateKey;
    public PublicKey publicKey;
}
```

setup() 是 Range Proofs 的发行者初始化步骤。
生成一个 16 字节的随机种子 seed，并使用 SHA-256 哈希函数计算出 s。
定义一个参数 k，其值为 2100 - 1978，即 122，这可能是范围的上限和下限之间的差。
使用 SHA-256 哈希函数重复对 s 进行 k 次哈希计算，得到最终的哈希值 c。
使用发行者的私钥对 c 进行 RSA 签名，得到 sig_c。
返回 s 和 sig_c，这将作为 Range Proofs 的一部分。

### Alice

Alice使用自己的私钥进行签名，并根据接收到的数据计算出 d_0，然后计算证明p，并将(p, sig_c)发送给Bob。

```
public class Alice {
    public Alice(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public String[] calProof(String[] receive) {
        SHA256 sha256 = new SHA256();

        s = receive[0];
        sig_c = receive[1];

        d_0 = 2000 - 1978;
        String tmp = s;
        for (int i = 0; i < d_0; i++)
            tmp = sha256.hash(tmp);
        p = tmp;

        return new String[]{p, sig_c};
    }

    public int d_0;
    public String p, c;
    public String s, sig_c;
    private PrivateKey privateKey;
    public PublicKey publicKey;
}
```

calProof() 用于计算 Range Proofs 的一部分。
接收一个包含两个元素的字符串数组 receive，其中第一个元素是 s，第二个元素是 sig_c。
将 s 和 sig_c 存储到相应的成员变量中。
定义一个参数 d_0，其值为 2000 - 1978，即 22，这可能是范围的上限和下限之间的差。
使用 SHA-256 哈希函数重复对 s 进行 d_0 次哈希计算，得到最终的哈希值 p。
返回 p 和 sig_c，这将作为 Range Proofs 的一部分。


### Bob

Bob 使用自己的私钥进行签名验证，根据接收到的数据计算出d_1，根据p计算c'，最后根据私钥对签名c'进行验证。

```
public class Bob {
    public Bob(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }
    public boolean verify(String[] receive) {
        SHA256 sha256 = new SHA256();
        d_1 = 2100 - 2000;

        p = receive[0];
        sig_c = receive[1];

        String tmp = p;
        for (int i = 0; i < d_1; i++)
            tmp = sha256.hash(tmp);
        c = tmp;

        sig_cc = Sign_RSA.sign(privateKey, c);
        if (sig_c.equalsIgnoreCase(sig_cc)) return true;
        return false;
    }

    public int d_1;
    public String p, sig_c, sig_cc, c;
    private PrivateKey privateKey;
    public PublicKey publicKey;
}
```

verify()用于验证 Range Proofs 的正确性。
接收一个包含两个元素的字符串数组 receive，其中第一个元素是 p，第二个元素是 sig_c。
将 p 和 sig_c 存储到相应的成员变量中。
定义一个参数 d_1，其值为 2100 - 2000，即 100，这可能是范围的上限和下限之间的差。
使用 SHA-256 哈希函数重复对 p 进行 d_1 次哈希计算，得到最终的哈希值 c。
使用 Bob 的私钥对 c 进行 RSA 签名，得到 sig_cc。
将 sig_c 和 sig_cc 进行比较，如果它们相等，返回 true，表示验证成功，否则返回 false，表示验证失败。



























