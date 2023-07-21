import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class User {
    // Member variables
    private final ECPoint publicKey;
    private final BigInteger privateKey;
    private final String identity;
    private final KGC kgc;
    private final BigInteger partialPrivateKey;
    private final ECPoint partialPublicKey;

    private byte[] order;

    // Constructor
    public User(KGC kgc, String identity) {
        this.identity = identity;
        this.kgc = kgc;

        // Generate private key and corresponding public key
        privateKey = kgc.generateCoPrimeInRange(kgc.getN());
        publicKey = kgc.getBasePoint().multiply(privateKey);

        // Extract partial public key and partial private key using KGC
        Object[] obj = kgc.extract(publicKey, identity);
        if (!verifyExtraction(obj)) {
            throw new IllegalArgumentException("Extraction verification failed for user: " + identity);
        }
        partialPublicKey = (ECPoint) obj[0];
        partialPrivateKey = (BigInteger) obj[1];
    }

    // Verify the extraction of partial public and private keys
    public boolean verifyExtraction(Object[] obj) {
        ECPoint partialPublicKey = (ECPoint) obj[0];
        BigInteger partialPrivateKey = (BigInteger) obj[1];
        ECPoint R = (ECPoint) obj[2];

        // Verify the extracted keys
        ECPoint sG = kgc.getBasePoint().multiply(partialPrivateKey);
        ECPoint h1 = kgc.getPublicKey().multiply(kgc.hash12(identity, publicKey));
        ECPoint computed_sG = partialPublicKey.add(h1);
        boolean isLegitKeys = computed_sG.equals(sG);

        ECPoint computed_R = sG.add(partialPublicKey.multiply(privateKey));
        boolean isLegitR = computed_R.equals(R);

        return isLegitKeys && isLegitR;
    }

    // Perform signcrypt operation on the given message
    public Object[] signcrypt(String message) {
        BigInteger f = kgc.generateCoPrimeInRange(kgc.getN());
        ECPoint F = kgc.getBasePoint().multiply(f);
        ECPoint V = partialPublicKey.add(kgc.getPublicKey().multiply(kgc.hash12(identity, publicKey)))
                .add(publicKey).multiply(f);
        byte[] h3 = kgc.hash3(V, F);
        byte[] messageBytes = message.getBytes();
        byte[] encryptedMessage = new byte[messageBytes.length];

        // Encrypt the message using XOR operation
        for (int i = 0; i < messageBytes.length; i++) {
            encryptedMessage[i] = (byte) (messageBytes[i] ^ h3[i]);
        }

        BigInteger mu = kgc.hash12(message, F);
        BigInteger u = mu.multiply(privateKey.add(partialPrivateKey)).add(f);

        return new Object[]{F, encryptedMessage, u};
    }

    // Perform unsigncrypt operation on the aggregated cipher text and public keys
    public Object[] unsigncrypt(Object[] aggregatedCipherText, List<Object[]> publicKeys) {
        List<ECPoint> aggregateF = (ArrayList<ECPoint>) aggregatedCipherText[0];
        List<byte[]> aggregateC = (ArrayList<byte[]>) aggregatedCipherText[1];
        BigInteger u = (BigInteger) aggregatedCipherText[2];
        ECPoint uG = kgc.getBasePoint().multiply(u);

        List<ECPoint> V = new ArrayList<>();
        List<byte[]> C = new ArrayList<>();
        ECPoint h2 = kgc.getCurve().getInfinity();
        ECPoint FSum = kgc.getCurve().getInfinity();

        ECPoint USum = kgc.getCurve().getInfinity();
        ECPoint h1Sum = kgc.getCurve().getInfinity();
        ECPoint YSum = kgc.getCurve().getInfinity();

        // Compute intermediate values for unsigncrypt
        for (Object[] publicKey : publicKeys) {
            String identity = (String) publicKey[0];
            ECPoint partialPublicKey = (ECPoint) publicKey[1];
            ECPoint pKey = (ECPoint) publicKey[2];
            ECPoint h1 = kgc.getPublicKey().multiply(kgc.hash12(identity, pKey));
            USum = USum.add(partialPublicKey);
            h1Sum = h1Sum.add(h1);
            YSum = YSum.add(pKey);
        }

        ECPoint CompleteSum = USum.add(h1Sum).add(YSum);
        if(order == null){
            return new Object[]{false,"Nothing to decrypt.".getBytes()};
        }
        byte[] recoveredMessage = new byte[order.length];

        // Decrypt the aggregated cipher text
        for (int i = 0; i < aggregateC.size(); i++) {
            V.add(aggregateF.get(i).multiply(partialPrivateKey.add(privateKey)));
            C.add(kgc.xorByteArrays(aggregateC.get(i), kgc.hash3(V.get(i), aggregateF.get(i))));
            h2 = h2.multiply(kgc.hash12(Arrays.toString(C.get(i)), V.get(i)));
            recoveredMessage = order.clone();
            FSum = FSum.add(aggregateF.get(i));
        }
        CompleteSum = CompleteSum.add(h2).add(FSum);
        boolean result = !uG.equals(CompleteSum);
        if(!result){
            recoveredMessage = "Digital Signature Cannot be verified".getBytes();
        }
        return new Object[]{result, recoveredMessage};
    }

    // Getters
    public ECPoint getPublicKey() {
        return publicKey;
    }

    public String getIdentity() {
        return identity;
    }

    public ECPoint getPartialPublicKey() {
        return partialPublicKey;
    }
    public void setOrder(byte[] order) {
        this.order = order;
    }
}
