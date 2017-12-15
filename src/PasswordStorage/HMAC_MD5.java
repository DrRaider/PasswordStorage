package PasswordStorage;

import java.util.Objects;

import static PasswordStorage.MD5.computeMD5;
import static PasswordStorage.MD5.toHexString;

class HMAC_MD5 {
    private static int BLOCK_SIZE = 64;
    private static int OUTPUT_SIZE = 16;
    private static byte IPAD = 0x36;
    private static byte OPAD = 0x5c;


    private static byte[] computeHMAC(byte[] message, byte[] key) {
        byte[] paddedKey = new byte[BLOCK_SIZE];
        if (key.length > BLOCK_SIZE) {
            paddedKey = computeMD5(key);
        }

        else if (key.length < BLOCK_SIZE) {
            System.arraycopy(key, 0, paddedKey, 0, key.length);
        }
        byte[] i_pad = new byte[BLOCK_SIZE];
        byte[] o_pad = new byte[BLOCK_SIZE];

        for (int i = 0; i < BLOCK_SIZE; i++) {
            i_pad[i] = (byte) (paddedKey[i] ^ IPAD);
            o_pad[i] = (byte) (paddedKey[i] ^ OPAD);
        }

        byte[] temp1 = new byte[BLOCK_SIZE + message.length];
        System.arraycopy(i_pad, 0, temp1, 0, BLOCK_SIZE);
        System.arraycopy(message, 0, temp1, BLOCK_SIZE, message.length);
        byte[] hmac = computeMD5(temp1);

        byte[] temp2 = new byte[BLOCK_SIZE + hmac.length];
        System.arraycopy(o_pad, 0, temp2, 0, BLOCK_SIZE);
        System.arraycopy(hmac, 0, temp2, BLOCK_SIZE, hmac.length);
        return computeMD5(temp2);
    }

    static void hmac(String message, String key) {
        byte[] b;
        if (Objects.equals("0x", key.substring(0, 2))) {
            String t = key.substring(2);
            b = new byte[t.length() / 2];
            for (int i = 0; i < b.length; i++) {
                int index = i * 2;
                int v = Integer.parseInt(t.substring(index, index + 2), 16);
                b[i] = (byte) v;
            }
        }
        else
            b = key.getBytes();

        System.out.println(
                "0x" + toHexString(computeHMAC((message).getBytes(), b))
                + " <== \"" + message + "\"" + " <== \"" + key + "\""
        );
    }
}
