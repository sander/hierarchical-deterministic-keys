// Run with Java 25+: java --add-modules java.se prototype.java

import module java.se;

void main() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyException {
    var kg = KeyPairGenerator.getInstance("EC");
    kg.initialize(new ECGenParameterSpec("NIST P-256"));

    var provider = kg.generateKeyPair();
    var wallet = kg.generateKeyPair();

    var salt = new byte[32];
    var index = 1;
    var info = new byte[0];

    var ka = KeyAgreement.getInstance("ECDH");
    var secretA = exchange(ka, provider.getPrivate(), hdk(wallet.getPublic(), salt, index, info)).generateSecret();
    var secretB = exchange(ka, wallet.getPrivate(), hdk(provider.getPublic(), salt, index, info)).generateSecret();

    if (!MessageDigest.isEqual(secretA, secretB)) throw new AssertionError();

    IO.println(HexFormat.of().formatHex(secretA));
}

static KeyAgreement exchange(KeyAgreement ka, PrivateKey sk, PublicKey pk) throws KeyException {
    ka.init(sk);
    ka.doPhase(pk, true);
    return ka;
}

/**
 * Hierarchical deterministic keys, assuming the input key is on the P-256 curve.
 */
ECPublicKey hdk(PublicKey key, byte[] salt, int index, byte[] info) throws NoSuchAlgorithmException {
    final var TAG = "HDK-v1.";
    final var SALT_SIZE = 32;

    if (salt.length != SALT_SIZE) throw new IllegalArgumentException();
    if (!(key instanceof ECPublicKey)) throw new IllegalArgumentException();

    var digest = MessageDigest.getInstance("SHA-256");
    var factory = KeyFactory.getInstance("EC");
    var agreement = KeyAgreement.getInstance("ECDH");

    var p256 = ((ECPublicKey) key).getParams();
    var prime = ((ECFieldFp) p256.getCurve().getField()).getP();

    digest.reset();
    digest.update(TAG.getBytes(StandardCharsets.US_ASCII));
    digest.update(salt);
    digest.update(ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(index).array());
    var factor = new BigInteger(1, digest.digest(info))
            .mod(p256.getOrder().subtract(BigInteger.ONE))
            .add(BigInteger.ONE);
    try {
        exchange(agreement, factory.generatePrivate(new ECPrivateKeySpec(factor, p256)), key);
    } catch (KeyException | InvalidKeySpecException e) {
        throw new RuntimeException(e);
    }

    var x = new BigInteger(1, agreement.generateSecret()).mod(prime);
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
