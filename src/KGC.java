import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.crypto.digests.SHA256Digest;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class KGC {
    // Member variables
    private final ECCurve curve;
    private final ECPoint basePoint;
    private final BigInteger n;
    private final BigInteger p;
    private final BigInteger x; // master key
    private final ECPoint pubKey; // system public key

    // Constructor
    public KGC(int k) {
        // Generate a large prime number
        p = generateLargePrime(k);

        // Retrieve curve parameters for secp256r1
        ECNamedCurveParameterSpec namedCurveParameterSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
        curve = namedCurveParameterSpec.getCurve();
        basePoint = namedCurveParameterSpec.getG();
        n = namedCurveParameterSpec.getN();

        // Generate master key (x) and compute the system public key
        x = generateCoPrimeInRange(n);
        pubKey = basePoint.multiply(x);
    }

    // Getters
    public ECCurve getCurve() {
        return curve;
    }

    public BigInteger getN() {
        return n;
    }

    public ECPoint getBasePoint() {
        return basePoint;
    }

    public ECPoint getPublicKey() {
        return pubKey;
    }

    // Compute the hash12 value
    public BigInteger hash12(String binaryString, ECPoint groupElement) {
        groupElement = groupElement.normalize();
        // Convert the binary string to a byte array
        byte[] binaryBytes = binaryString.getBytes(StandardCharsets.UTF_8);
        // Hash the binary string using SHA-256
        byte[] hash = hashFunction(binaryBytes);
        // Convert the hash to a BigInteger
        BigInteger hashBigInt = new BigInteger(1, hash);
        // Multiply the hash value with the x-coordinate of the groupElement using elliptic curve multiplication
        BigInteger result = groupElement.getAffineXCoord().toBigInteger().multiply(hashBigInt);
        // Reduce the result modulo p to ensure it is in the range of Z∗p
        result = result.mod(p);
        // Return the resulting value
        return result;
    }

    // Compute the hash3 value
    public byte[] hash3(ECPoint groupElement1, ECPoint groupElement2) {
        groupElement1 = groupElement1.normalize();
        groupElement2 = groupElement2.normalize();
        // Concatenate the x-coordinates of the two group elements
        BigInteger x1 = groupElement1.getAffineXCoord().toBigInteger();
        BigInteger x2 = groupElement2.getAffineXCoord().toBigInteger();
        byte[] concatenatedBytes = concatenateBigIntegers(x1, x2);
        // Hash the concatenated bytes using a secure hash function, such as SHA-256
        return hashFunction(concatenatedBytes);
    }

    // Extract the partial public/private keys for a user
    public Object[] extract(ECPoint userPublicKey, String identity) {
        BigInteger v = generateCoPrimeInRange(n);
        ECPoint partialPublicKey = basePoint.multiply(v);

        BigInteger h1 = hash12(identity, userPublicKey);
        BigInteger partialPrivateKey = v.add(x.multiply(h1)).mod(n);

        ECPoint sG = basePoint.multiply(partialPrivateKey);
        ECPoint vY = userPublicKey.multiply(v);
        ECPoint R = sG.add(vY);

        return new Object[]{partialPublicKey, partialPrivateKey, R};
    }

    // Aggregate cipher texts
    public Object[] aggregate(List<Object[]> cipherTexts) {
        List<ECPoint> aggregateF = new ArrayList<>();
        List<byte[]> aggregateEncryptedMessage = new ArrayList<>();
        BigInteger sumU = BigInteger.ZERO;

        for (Object[] cipherText : cipherTexts) {
            ECPoint F = (ECPoint) cipherText[0];
            byte[] encryptedMessage = (byte[]) cipherText[1];
            BigInteger u = (BigInteger) cipherText[2];

            aggregateF.add(F);
            aggregateEncryptedMessage.add(encryptedMessage);
            sumU = sumU.add(u);
        }

        return new Object[]{aggregateF, aggregateEncryptedMessage, sumU};
    }

    // Helper method to compute the hash of a byte array using SHA-256
    private byte[] hashFunction(byte[] input) {
        SHA256Digest digest = new SHA256Digest();
        digest.update(input, 0, input.length);
        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);
        return output;
    }

    // Helper method to perform XOR operation on two byte arrays
    public byte[] xorByteArrays(byte[] array1, byte[] array2) {
        int length = Math.max(array1.length, array2.length);
        byte[] result = new byte[length];
        for (int i = 0; i < length; i++) {
            byte b1 = (i < array1.length) ? array1[i] : 0;
            byte b2 = (i < array2.length) ? array2[i] : 0;
            result[i] = (byte) (b1 ^ b2);
        }
        return result;
    }

    // Helper method to concatenate multiple BigIntegers into a byte array
    private byte[] concatenateBigIntegers(BigInteger... integers) {
        int totalLength = 0;
        for (BigInteger integer : integers) {
            totalLength += integer.toByteArray().length;
        }

        byte[] concatenatedBytes = new byte[totalLength];
        int currentIndex = 0;
        for (BigInteger integer : integers) {
            byte[] bytes = integer.toByteArray();
            System.arraycopy(bytes, 0, concatenatedBytes, currentIndex, bytes.length);
            currentIndex += bytes.length;
        }

        return concatenatedBytes;
    }

    // Helper method to generate a large prime number of the specified bit length
    private BigInteger generateLargePrime(int bitLength) {
        SecureRandom random = new SecureRandom();
        return BigInteger.probablePrime(bitLength, random);
    }

    // Helper method to generate a random co-prime value within the range of n
    public BigInteger generateCoPrimeInRange(BigInteger n) {
        SecureRandom random = new SecureRandom();
        BigInteger x;
        do {
            x = new BigInteger(n.bitLength(), random);
        } while (x.compareTo(BigInteger.ONE) < 0 || x.compareTo(n) >= 0);
        return x;
    }
}
