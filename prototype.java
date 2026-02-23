// Run with Java 25+: java --add-modules java.se prototype.java

import module java.se;

void main() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyException {
    var kg = KeyPairGenerator.getInstance("EC");
    kg.initialize(new ECGenParameterSpec("NIST P-256"));

    var provider = kg.generateKeyPair();
    var wallet = kg.generateKeyPair();

    var ka = KeyAgreement.getInstance("ECDH");
    var params = new HierarchicalDeterministicKeys(new byte[32], 1, new byte[0]);
    var secretA = exchange(ka, provider.getPrivate(), params.derive(wallet.getPublic())).generateSecret();
    var secretB = exchange(ka, wallet.getPrivate(), params.derive(provider.getPublic())).generateSecret();

    if (!MessageDigest.isEqual(secretA, secretB)) throw new AssertionError();

    IO.println(HexFormat.of().formatHex(secretA));
}

static KeyAgreement exchange(KeyAgreement ka, PrivateKey sk, PublicKey pk) throws KeyException {
    ka.init(sk);
    ka.doPhase(pk, true);
    return ka;
}

record HierarchicalDeterministicKeys(byte[] salt, int index, byte[] info) {
    private static final int SALT_SIZE = 32;
    private static final String TAG = "HDK-v1.";

    /**
     * Assumes the input key is on the P-256 curve.
     *
     * Returns (x, y) or (x, p-y). This is OK for wallet applications.
     */
    ECPublicKey derive(PublicKey key) throws NoSuchAlgorithmException {
        if (salt.length != SALT_SIZE) throw new IllegalArgumentException();
        if (!(key instanceof ECPublicKey)) throw new IllegalArgumentException();

        var digest = MessageDigest.getInstance("SHA-256");
        var factory = KeyFactory.getInstance("EC");
        var agreement = KeyAgreement.getInstance("ECDH");

        var p256 = ((ECPublicKey) key).getParams();
        var factor = factor(digest, p256);
        try {
            exchange(agreement, factory.generatePrivate(new ECPrivateKeySpec(factor, p256)), key);
        } catch (KeyException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }

        var sharedSecret = agreement.generateSecret();
        return recover(factory, p256, sharedSecret);
    }

    private BigInteger factor(MessageDigest digest, ECParameterSpec p256) {
        digest.reset();
        digest.update(TAG.getBytes(StandardCharsets.US_ASCII));
        digest.update(salt);
        digest.update(ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(index).array());
        return new BigInteger(1, digest.digest(info))
                .mod(p256.getOrder().subtract(BigInteger.ONE))
                .add(BigInteger.ONE);
    }

    private ECPublicKey recover(KeyFactory factory, ECParameterSpec p256, byte[] sharedSecret) {
        var prime = ((ECFieldFp) p256.getCurve().getField()).getP();
        var x = new BigInteger(1, sharedSecret).mod(prime);
        var y = x.modPow(BigInteger.valueOf(3), prime)
                .add(p256.getCurve().getA().multiply(x))
                .add(p256.getCurve().getB())
                .mod(prime)
                .modPow(prime.add(BigInteger.ONE).shiftRight(2), prime);
        var point = new ECPoint(x, (y.testBit(0)) ? prime.subtract(y) : y);
        try {
            return (ECPublicKey) factory.generatePublic(new ECPublicKeySpec(point, p256));
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }
}
