package PasswordStorage;


import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.security.SecureRandom;
import java.util.Arrays;


class MD5 {

    /** binary integer part of the sines of integers (Radians) */
    private static final int[] k = {
            0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee, //K[ 0.. 3]
            0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501, //K[ 4.. 7]
            0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be, //K[ 8..11]
            0x6b901122,0xfd987193,0xa679438e,0x49b40821, //K[12..15]
            0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa, //K[16..19]
            0xd62f105d, 0x2441453,0xd8a1e681,0xe7d3fbc8, //K[20..23]
            0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed, //K[24..27]
            0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a, //K[28..31]
            0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c, //K[32..35]
            0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70, //K[36..39]
            0x289b7ec6,0xeaa127fa,0xd4ef3085, 0x4881d05, //K[40..43]
            0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665, //K[44..47]
            0xf4292244,0x432aff97,0xab9423a7,0xfc93a039, //K[48..51]
            0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1, //K[52..55]
            0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1, //K[56..59]
            0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391  //K[60..63]
    };

    /** specifies the per-round shift amounts */
    private static final int[] s = {
            7, 12, 17, 22,
            5,  9, 14, 20,
            4, 11, 16, 23,
            6, 10, 15, 21
    };
    private static int ORIGIN_A = 0x67452301;
    private static int ORIGIN_B = (int) 0xEFCDAB89; //B
    private static int ORIGIN_C = (int) 0x98BADCFE; //C
    private static int ORIGIN_D = 0x10325476; //D

    static byte[] computeMD5(byte[] message) {
        int messageLength = message.length;

        // append "1" at the end of the message
        byte[] oneToAppend = new byte[1];
        oneToAppend[0] = (byte) 0x80;
        byte[] messageWithOne = new byte[messageLength + 1];
        System.arraycopy(message, 0, messageWithOne, 0, message.length);
        System.arraycopy(oneToAppend, 0, messageWithOne, messageLength,1);
        messageLength += 1;

        // append "0" bit until messageLength ≡ 448 (mod 512)
        ByteArrayOutputStream zeroToAppend = new ByteArrayOutputStream();
        while (messageLength % 64 != 56 % 64) {
            zeroToAppend.write((byte) 0x00);
            messageLength += 1;
        }

        byte[] messagePa = new byte[messageLength];
        System.arraycopy(messageWithOne, 0, messagePa, 0, messageWithOne.length);
        System.arraycopy(
                zeroToAppend.toByteArray(),
                0,
                messagePa,
                messageWithOne.length,
                messageLength - messageWithOne.length
        );

        // append original length in bits mod 2^64 to message
        ByteArrayOutputStream msgToAppend = new ByteArrayOutputStream();
        long messageLenBits = (long)message.length << 3;
        for (int l = 0; l < 8; l++) {
            msgToAppend.write((byte)messageLenBits);
            messageLenBits >>>= 8;
            messageLength += 1;
        }
        byte[] messagePadded = new byte[messageLength];
        System.arraycopy(messagePa, 0, messagePadded, 0, messagePa.length);
        System.arraycopy(
                msgToAppend.toByteArray(),
                0,
                messagePadded,
                messagePa.length,
                msgToAppend.toByteArray().length
        );

        //Get 512 bit (64 byte) chunks of padded message
        byte[][] chunks = new byte[messageLength / 64][];
        int i = 0, j = 0;
        while (i < messageLength) {
            chunks[j] = new byte[64];
            chunks[j] = Arrays.copyOfRange(messagePadded, i, i + 64);
            i += 64;
            j++;
        }

        /*
      A four-word buffer (A,B,C,D) is used to compute the message digest.
      Here each of A, B, C, D is a 32-bit register. These registers are
      initialized to the following values in hexadecimal, low-order bytes
      first):
     */
        int A = ORIGIN_A;
        int B = ORIGIN_B;
        int C = ORIGIN_C;
        int D = ORIGIN_D;
        for (byte[] c : chunks) {
            // break chunks into sixteen 32-bit words
            IntBuffer intBuf = ByteBuffer.wrap(c).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
            int[] M = new int[intBuf.remaining()];
            intBuf.get(M);

            //Initialize hash value for this chunk:
            int WORD_A = A;
            int WORD_B = B;
            int WORD_C = C;
            int WORD_D = D;

            //Main loop:
            for (int m = 0; m < 64; m++) { // iterate through each chunk byte by byte
                int F;
                int g = m;
                int div16 = m >>> 4;
                if (m <= 15) {
                    F = (B & C) | (~B & D);
                } else if (m <= 31) {
                    F = (D & B) | ((~D) & C);
                    g = (5 * g + 1) % 16;
                } else if (m <= 47) {
                    F = B ^ C ^ D;
                    g = (3 * g + 5) % 16;
                } else {
                    F = C ^ (B | (~D));
                    g = (7 * g) % 16;
                }
                F = F + A + k[m] + M[g];
                A = D;
                D = C;
                C = B;
                B = B + Integer.rotateLeft(F, s[(div16 << 2) | (m & 3)]);

            }

            A += WORD_A;
            B += WORD_B;
            C += WORD_C;
            D += WORD_D;
        }

        ByteBuffer md5 = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        for (int n : new int[]{A, B, C, D})  {
            md5.putInt(n);
        }
        return md5.array();
    }

    static String toHexString(byte[] b)
    {
        StringBuilder sb = new StringBuilder();
        for (byte aB : b) {
            sb.append(String.format("%02X", aB & 0xFF));
        }
        return sb.toString();
    }

    private static byte[] generateKey() {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[32];
        random.nextBytes(bytes);
        return bytes;
    }

    static void md5(String[] password) {
        for (String s : password) {
            System.out.println("0x" + toHexString(computeMD5((s).getBytes())) + " <== \"" + s + "\"");
        }
    }

    static void md5Salted(String[] password) {
        String[] salts = new String[password.length];
        for (int i = 0; i < password.length; i++) {
            salts[i] = toHexString(generateKey());
        }
        int index = 0;
        for (String s : password) {
            System.out.println(
                    "0x" + toHexString(computeMD5((s + salts[index]).getBytes()))
                    + " <== \"" + s + "\"" + " <== \"" + salts[index] + "\""
            );
            index++;
        }
    }
}
