// Illustrative prototype, not production code. Run with Java 25+: java -ea prototype.java

void main() throws Exception {
    var random = Crypto.random();

    var holder = new Holder(Crypto.keyPair("X25519", random), Crypto.keyPair("EC", random));
    var issuer = new Issuer(Crypto.keyPair("X25519", random));
    var verifier = new Verifier(Crypto.keyPair("EC", random));

    var request = holder.credentialRequest();
    var response = issuer.issue(request);
    var transcript = "transcript".getBytes();

    assert verifier.verifyPossessionECDH(holder.provePossessionECDH(response, verifier.publicKey()));
    assert verifier.verifyPossessionECDSA(holder.provePossessionECDSA(response, transcript), transcript);

    printTestVectors(holder, response);
    IO.println("HDK prototype tests passed");
}

record CredentialRequest(PublicKey ephemeral, ECPublicKey parent) {}
record CredentialResponse(PublicKey ephemeral, List<ECPublicKey> publicKeys) {}
record ProofOfPossession(ECPublicKey publicKey, byte[] bytes) {}

record Issuer(KeyPair ephemeral) {
    CredentialResponse issue(CredentialRequest request) throws Exception {
        var bk = Crypto.agree("X25519", ephemeral.getPrivate(), request.ephemeral());
        return new CredentialResponse(ephemeral.getPublic(), List.of(
                deriveChildPK(request.parent(), bk, 0),
                deriveChildPK(request.parent(), bk, 1)));
    }

    private ECPublicKey deriveChildPK(ECPublicKey parent, byte[] bk, int index) throws Exception { return blindPK(parent, bk, context(parent, index)); }
}

record Holder(KeyPair ephemeral, KeyPair parent) {
    private record Credential(ECPublicKey publicKey, BigInteger blinding) {}

    CredentialRequest credentialRequest() { return new CredentialRequest(ephemeral.getPublic(), parentPK()); }

    ProofOfPossession provePossessionECDH(CredentialResponse response, ECPublicKey peer) throws Exception {
        var credential = credential(response, 0);
        return new ProofOfPossession(credential.publicKey(), Crypto.agree("ECDH", parent.getPrivate(),
                Crypto.scaleForEcdh(peer, credential.blinding())));
    }

    ProofOfPossession provePossessionECDSA(CredentialResponse response, byte[] transcript) throws Exception {
        var credential = credential(response, 1);
        return new ProofOfPossession(credential.publicKey(),
                ECDSA.signChildViaParent(parent.getPrivate(), credential.blinding(), transcript));
    }

    private Credential credential(CredentialResponse response, int index) throws Exception {
        var bk = Crypto.agree("X25519", ephemeral.getPrivate(), response.ephemeral());
        var ctx = context(parentPK(), index);
        var childSk = blindSK(((ECPrivateKey) parent.getPrivate()).getS(), bk, ctx);
        var publicKey = response.publicKeys().get(index);
        assert Crypto.mul(Crypto.ecPublic(Crypto.P256.getGenerator()), childSk).getW().equals(publicKey.getW());
        return new Credential(publicKey, h(bk, ctx));
    }

    private ECPublicKey parentPK() { return (ECPublicKey) parent.getPublic(); }
}

record Verifier(KeyPair key) {
    ECPublicKey publicKey() { return (ECPublicKey) key.getPublic(); }
    boolean verifyPossessionECDH(ProofOfPossession proof) throws Exception { return Arrays.equals(proof.bytes(), Crypto.agree("ECDH", key.getPrivate(), proof.publicKey())); }
    boolean verifyPossessionECDSA(ProofOfPossession proof, byte[] transcript) throws Exception { return ECDSA.verify(proof.publicKey(), transcript, proof.bytes()); }
}

// HDK

static BigInteger h(byte[] bk, byte[] ctx) throws Exception { return new BigInteger(1, MessageDigest.getInstance("SHA-256").digest(Crypto.concat(bk, ctx))).mod(Crypto.N.subtract(BigInteger.ONE)).add(BigInteger.ONE); }
static ECPublicKey blindPK(ECPublicKey pk, byte[] bk, byte[] ctx) throws Exception { return Crypto.mul(pk, h(bk, ctx)); }
static BigInteger blindSK(BigInteger sk, byte[] bk, byte[] ctx) throws Exception { return sk.multiply(h(bk, ctx)).mod(Crypto.N); }
static byte[] context(ECPublicKey pk, int index) { return Crypto.concat(Crypto.encode(pk), ByteBuffer.allocate(4).putInt(index).array()); }

static class ECDSA {
    static byte[] signChildViaParent(PrivateKey parent, BigInteger b, byte[] msg) throws Exception {
        var z = new BigInteger(1, MessageDigest.getInstance("SHA-256").digest(msg));
        var signer = java.security.Signature.getInstance("NONEwithECDSAinP1363Format");
        signer.initSign(parent);
        signer.update(Crypto.i2osp(z.multiply(b.modInverse(Crypto.N)).mod(Crypto.N)));
        var sig = signer.sign();
        var s = new BigInteger(1, Arrays.copyOfRange(sig, 32, 64)).multiply(b).mod(Crypto.N);
        System.arraycopy(Crypto.i2osp(s), 0, sig, 32, 32);
        return sig;
    }

    static boolean verify(PublicKey pk, byte[] msg, byte[] sig) throws Exception {
        var verifier = java.security.Signature.getInstance("SHA256withECDSAinP1363Format");
        verifier.initVerify(pk);
        verifier.update(msg);
        return verifier.verify(sig);
    }
}

static class Crypto {
    static final ECParameterSpec P256 = p256();
    static final EllipticCurve CURVE = P256.getCurve();
    static final BigInteger N = P256.getOrder();
    static final BigInteger P = ((ECFieldFp) CURVE.getField()).getP();

    private static ECParameterSpec p256() {
        try {
            var parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256r1"));
            return parameters.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException e) { throw new ExceptionInInitializerError(e); }
    }

    static SecureRandom random() throws Exception {
        var random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed("HDK test vectors".getBytes(StandardCharsets.US_ASCII));
        return random;
    }

    static KeyPair keyPair(String algorithm, SecureRandom random) throws Exception {
        var kg = KeyPairGenerator.getInstance(algorithm);
        if (algorithm.equals("EC")) kg.initialize(P256, random);
        else kg.initialize(NamedParameterSpec.X25519, random);
        return kg.generateKeyPair();
    }

    static byte[] agree(String algorithm, PrivateKey sk, PublicKey pk) throws Exception {
        var ka = KeyAgreement.getInstance(algorithm);
        ka.init(sk);
        ka.doPhase(pk, true);
        return ka.generateSecret();
    }

    static BigInteger xmul(ECPublicKey pk, BigInteger k) throws Exception { return new BigInteger(1, agree("ECDH", ecPrivate(k), pk)); }

    // JCA ECDH gives x(k*pk). Reconstruct either point; its sign is irrelevant to ECDH.
    static ECPublicKey scaleForEcdh(ECPublicKey pk, BigInteger k) throws Exception {
        var x = xmul(pk, k);
        return ecPublic(new ECPoint(x, y2(x).modPow(P.add(BigInteger.ONE).shiftRight(2), P)));
    }

    // Recover exact k*pk from x(k*pk) and x((k+1)*pk), both obtained through ECDH.
    static ECPublicKey mul(ECPublicKey pk, BigInteger k) throws Exception {
        var q = pk.getW();
        if (k.equals(N.subtract(BigInteger.ONE))) return ecPublic(new ECPoint(q.getAffineX(), P.subtract(q.getAffineY()).mod(P)));

        var x = xmul(pk, k);
        var xn = xmul(pk, k.add(BigInteger.ONE));
        var d = x.subtract(q.getAffineX()).pow(2).multiply(xn.add(x).add(q.getAffineX())).mod(P);
        var y = y2(x).add(q.getAffineY().pow(2)).subtract(d).multiply(q.getAffineY().shiftLeft(1).modInverse(P)).mod(P);
        return ecPublic(new ECPoint(x, y));
    }

    private static BigInteger y2(BigInteger x) { return x.pow(3).add(CURVE.getA().multiply(x)).add(CURVE.getB()).mod(P); }
    static PrivateKey ecPrivate(BigInteger k) throws Exception { return KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(k, P256)); }
    static ECPublicKey ecPublic(ECPoint p) throws Exception { return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(p, P256)); }

    static byte[] encode(ECPublicKey pk) {
        var p = pk.getW();
        return concat(new byte[] {4}, i2osp(p.getAffineX()), i2osp(p.getAffineY()));
    }

    static String hex(byte[] bytes) { return HexFormat.of().formatHex(bytes); }

    static byte[] i2osp(BigInteger n) {
        var raw = n.toByteArray();
        var out = new byte[32];
        System.arraycopy(raw, Math.max(0, raw.length - 32), out, Math.max(0, 32 - raw.length), Math.min(32, raw.length));
        return out;
    }

    static byte[] concat(byte[]... xs) {
        var out = new byte[Arrays.stream(xs).mapToInt(x -> x.length).sum()];
        for (int i = 0, p = 0; i < xs.length; p += xs[i].length, i++) System.arraycopy(xs[i], 0, out, p, xs[i].length);
        return out;
    }
}

static void printTestVectors(Holder holder, CredentialResponse response) throws Exception {
    var parent = (ECPrivateKey) holder.parent().getPrivate();
    var parentPK = (ECPublicKey) holder.parent().getPublic();
    var shared = Crypto.agree("X25519", holder.ephemeral().getPrivate(), response.ephemeral());

    IO.println("sk_parent = " + Crypto.hex(Crypto.i2osp(parent.getS())));
    IO.println("pk_parent = " + Crypto.hex(Crypto.encode(parentPK)));
    IO.println("shared_secret = " + Crypto.hex(shared));

    for (int index = 0; index < response.publicKeys().size(); index++) {
        var ctx = context(parentPK, index);
        IO.println("\nFor Credential " + index + ":\n");
        IO.println("index = %08x".formatted(index));
        IO.println("ctx = " + Crypto.hex(ctx));
        IO.println("b = " + Crypto.hex(Crypto.i2osp(h(shared, ctx))));
        IO.println("sk_child = " + Crypto.hex(Crypto.i2osp(blindSK(parent.getS(), shared, ctx))));
        IO.println("pk_child = " + Crypto.hex(Crypto.encode(response.publicKeys().get(index))));
    }
}
