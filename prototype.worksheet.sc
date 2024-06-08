import java.security.MessageDigest
import java.util.HexFormat
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

type OS = Array[Byte]
case class Point(x: BigInt, y: BigInt)

// https://neuromancer.sk/std/nist/P-256
val p = BigInt("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
val a = BigInt(-3)
val b = BigInt("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
val n = BigInt("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
val G = Point(
  BigInt("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
  BigInt("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)
)

extension (k: BigInt) infix def pmod(m: BigInt) = if (k < 0) m - (-k % m) else k % m

assert((BigInt(-3) pmod BigInt(5)) == BigInt(2))

extension (P: Point)
  def isElement = P match { case Point(x, y) => (y * y - x * x * x - a * x - b) % p == 0 }
  def +(Q: Point) =
    val (Point(x1, y1), Point(x2, y2)) = (P, Q)
    val m =
      if (x1 == x2) (BigInt(3) * x1 * x1 + a) * (y1 * 2).modInverse(p)
      else (y1 - y2) * (x1 - x2).modInverse(p)
    val x3 = m * m - x1 - x2
    val y3 = y1 + m * (x3 - x1)
    Point(x3 pmod p, -y3 pmod p)

assert(G.isElement)

extension (k: BigInt)
  def os: OS = k.toByteArray match
    case os if os.head == 0x00 => os.drop(1)
    case os                    => os
  def scalarBaseMult: Point = scalarMult(G)
  def scalarMult(P: Point): Point = (P, k) match
    case (P, k) if k < 0 => (k pmod n).scalarMult(P)
    case (P, k) => (0 to k.bitLength).foldLeft(null.asInstanceOf[Point], P) {
        case ((null, addend), i) if k.testBit(i)   => (addend, addend + addend)
        case ((null, addend), _)                   => (null, addend + addend)
        case ((result, addend), i) if k.testBit(i) => (result + addend, addend + addend)
        case ((result, addend), _)                 => (result, addend + addend)
      }._1

def randomScalar() = BigInt(1, util.Random.nextBytes(n.bitLength / 8 + 8)) % (n - 1) + 1

assert(BigInt(2).scalarMult(G).isElement)
assert(BigInt(2).scalarMult(G) == G + G)
assert {
  val k1 = randomScalar()
  val k2 = randomScalar()
  k1.scalarBaseMult + k2.scalarBaseMult == (k1 + k2).scalarBaseMult
}

assert {
  val alice = randomScalar()
  val bob = randomScalar()
  bob.scalarMult(alice.scalarBaseMult) == alice.scalarMult(bob.scalarBaseMult)
}

def strxor(b: OS, c: OS) = (b zip c).map { case (i, j) => (i ^ j).toByte }
def SHA256(msg: OS) = MessageDigest.getInstance("SHA-256").digest(msg)
def I2OSP(i: BigInt, len: Int): OS = Array.fill[Byte](len - i.os.length)(0) || i.os
def OS2IP(os: OS): BigInt = BigInt(1, os)

def expandMessageXmd(msg: OS, DST: OS, lenInBytes: Int) =
  val DST_prime = DST || I2OSP(DST.length, 1)
  lazy val b: LazyList[OS] = SHA256(
    Array.fill[Byte](64)(0) || msg || I2OSP(lenInBytes, 2) || I2OSP(0, 1) || DST_prime
  ) #:: SHA256(b.head || I2OSP(1, 1) || DST_prime) #:: b.tail.zip(LazyList.from(2)).map {
    case (prev, i) => SHA256(strxor(b.head, prev) || I2OSP(i, 1) || DST_prime)
  }
  b.flatten.drop(32).take(lenInBytes).toArray
def hashToField(DST: OS, order: BigInt)(msg: OS) = OS2IP(expandMessageXmd(msg, DST, 48)) mod order

extension (s: String) def parseHex: OS = HexFormat.of().parseHex(s)
extension (b: OS)
  def toHex: String = HexFormat.of().formatHex(b)
  infix def ||(c: OS) = b concat c

// https://www.rfc-editor.org/rfc/rfc9380.html#name-expand_message_xmdsha-256
assert(
  expandMessageXmd(
    "".getBytes,
    "QUUX-V01-CS02-with-expander-SHA256-128".getBytes,
    0x20
  ) sameElements "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235".parseHex
)
assert(
  expandMessageXmd(
    "abc".getBytes,
    "QUUX-V01-CS02-with-expander-SHA256-128".getBytes,
    0x20
  ) sameElements "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615".parseHex
)
assert(
  expandMessageXmd(
    "".getBytes,
    "QUUX-V01-CS02-with-expander-SHA256-128".getBytes,
    0x80
  ) sameElements
    "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbee0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dcc541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced"
      .parseHex
)

// https://www.rfc-editor.org/rfc/rfc6090#section-4.2
def ECDH(pk: Point, sk: BigInt): OS = sk.scalarMult(pk).x.toByteArray

assert {
  val alice = randomScalar()
  val bob = randomScalar()
  ECDH(bob.scalarBaseMult, alice) sameElements ECDH(alice.scalarBaseMult, bob)
}

val DST_ext = "ARKG-P256ADD-ECDH".getBytes

object BL:
  def generateKeyPair() = randomScalar() match { case sk => (sk.scalarBaseMult, sk) }
  private def h(info: OS) = hashToField("ARKG-BL-EC.".getBytes || DST_ext || info, n)
  def blindPublicKey(pk: Point, tau: OS, info: OS) = pk + h(info)(tau).scalarBaseMult
  def blindPrivateKey(sk: BigInt, tau: OS, info: OS) = sk + h(info)(tau)

assert {
  val (pk, sk) = BL.generateKeyPair()
  val tau = "tau".getBytes
  val info = "info".getBytes
  BL.blindPublicKey(pk, tau, info) == BL.blindPrivateKey(sk, tau, info).scalarBaseMult
}

def HMAC(key: OS, msg: OS) =
  val mac = Mac.getInstance("HmacSHA256")
  mac.init(SecretKeySpec(key, "HmacSHA256"))
  mac.doFinal(msg)
object HKDF:
  def extract(salt: OS = Array.fill(32) { 0 }, IKM: OS) = HMAC(salt, IKM)
  def expand(PRK: OS, info: OS, L: Int) =
    lazy val T: LazyList[OS] = Array.emptyByteArray #:: T.zip(LazyList.from(1)).map {
      case (prev, i) => HMAC(PRK, prev || info :+ i.toByte)
    }
    T.flatten.take(L).toArray

// https://www.rfc-editor.org/rfc/rfc5869#appendix-A
assert {
  val PRK = HKDF.extract(
    "000102030405060708090a0b0c".parseHex,
    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b".parseHex
  )
  val OKM = HKDF.expand(PRK, "f0f1f2f3f4f5f6f7f8f9".parseHex, 42)
  (PRK sameElements "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5".parseHex) &&
  (OKM sameElements
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865".parseHex)
}

def ECP2OS(P: Point) = I2OSP(P.x, 32) || I2OSP(P.y, 32)
def OS2ECP(b: OS) =
  val (bx, by) = b.splitAt(32)
  Point(BigInt(1, bx), BigInt(1, by))

object KEM:
  private def mk(prk: OS, info: OS) = HKDF
    .expand(prk, "ARKG-KEM-HMAC-mac.".getBytes || DST_ext || info, 32)
  private def t(prk: OS, info: OS) =
    HMAC(mk(prk, info), "ARKG-KEM-HMAC.".getBytes || DST_ext || info).take(16)
  private def k(prk: OS, info: OS, k_prime: OS) = HKDF
    .expand(prk, "ARKG-KEM-HMAC-shared.".getBytes || DST_ext || info, k_prime.length)
  def generateKeyPair() = randomScalar() match { case sk => (sk.scalarBaseMult, sk) }
  def encaps(pk: Point, info: OS) =
    val (pk_prime, sk_prime) = generateKeyPair()
    val (k_prime, c_prime) = (ECDH(pk, sk_prime), ECP2OS(pk_prime))
    val prk = HKDF.extract(IKM = k_prime)
    (k(prk, info, k_prime), t(prk, info) || c_prime)
  def decaps(sk: BigInt, c: OS, info: OS) =
    val (t_in, c_prime) = c.splitAt(16)
    val pk_prime = OS2ECP(c_prime)
    val k_prime = ECDH(pk_prime, sk)
    val prk = HKDF.extract(IKM = k_prime)
    assert(t_in sameElements t(prk, info), "Invalid key handle")
    k(prk, info, k_prime)

assert {
  val (pk, sk) = KEM.generateKeyPair()
  val info = "info".getBytes
  val (k, c) = KEM.encaps(pk, info)
  KEM.decaps(sk, c, info) sameElements k
}

object ARKG:
  private def info_kem(info: OS) = "ARKG-Derive-Key-KEM.".getBytes || info
  private def info_bl(info: OS) = "ARKG-Derive-Key-BL.".getBytes || info
  def generateSeed() = (KEM.generateKeyPair(), BL.generateKeyPair()) match
    case ((pk_kem, sk_kem), (pk_bl, sk_bl)) => ((pk_kem, pk_bl), (sk_kem, sk_bl))
  def derivePublicKey(pk: (Point, Point), info: OS) =
    val (pk_kem, pk_bl) = pk
    val (tau, c) = KEM.encaps(pk_kem, info_kem(info))
    (BL.blindPublicKey(pk_bl, tau, info_bl(info)), c)
  def derivePrivateKey(sk: (BigInt, BigInt), kh: OS, info: OS) =
    val (sk_kem, sk_bl) = sk
    val tau = KEM.decaps(sk_kem, kh, info_kem(info))
    BL.blindPrivateKey(sk_bl, tau, info_bl(info))

assert {
  val (pk, sk) = ARKG.generateSeed()
  val info = "info".getBytes
  val (pk_prime, kh) = ARKG.derivePublicKey(pk, info)
  pk_prime == ARKG.derivePrivateKey(sk, kh, info).scalarBaseMult
}
