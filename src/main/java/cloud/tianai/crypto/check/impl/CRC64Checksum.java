package cloud.tianai.crypto.check.impl;

import cloud.tianai.crypto.check.EnhanceChecksum;

/**
 * @Author: 天爱有情
 * @date 2021/11/26 14:25
 * @Description CRC64 Checksum
 */
public class CRC64Checksum implements EnhanceChecksum<Long> {

    private final static long POLY = (long) 0xc96c5795d7870f42L; // ECMA-182

    /* CRC64 calculation table. */
    private final static long[] table;

    /* Current CRC value. */
    private long value;

    static {
        table = new long[256];
        for (int n = 0; n < 256; n++) {
            long crc = n;
            for (int k = 0; k < 8; k++) {
                if ((crc & 1) == 1) {
                    crc = (crc >>> 1) ^ POLY;
                } else {
                    crc = (crc >>> 1);
                }
            }
            table[n] = crc;
        }
    }

    public CRC64Checksum() {
        this.value = 0;
    }

    public CRC64Checksum(long value) {
        this.value = value;
    }

    public CRC64Checksum(byte[] b, int len) {
        this.value = 0;
        update(b, len);
    }

    /**
     * Construct new CRC64 instance from byte array.
     **/
    public static CRC64Checksum fromBytes(byte[] b) {
        long l = 0;
        for (int i = 0; i < 4; i++) {
            l <<= 8;
            l ^= (long) b[i] & 0xFF;
        }
        return new CRC64Checksum(l);
    }

    /**
     * Get 8 byte representation of current CRC64 value.
     **/
    public byte[] getBytes() {
        byte[] b = new byte[8];
        for (int i = 0; i < 8; i++) {
            b[7 - i] = (byte) (this.value >>> (i * 8));
        }
        return b;
    }

    @Override
    public Long getCheckValue() {
        return this.value;
    }

    /**
     * Get long representation of current CRC64 value.
     **/
    @Override
    public long getValue() {
        return this.value;
    }

    /**
     * Update CRC64 with new byte block.
     **/
    public void update(byte[] b, int len) {
        int idx = 0;
        this.value = ~this.value;
        while (len > 0) {
            this.value = table[((int) (this.value ^ b[idx])) & 0xff] ^ (this.value >>> 8);
            idx++;
            len--;
        }
        this.value = ~this.value;
    }

    /**
     * Update CRC64 with new byte.
     **/
    public void update(byte b) {
        this.value = ~this.value;
        this.value = table[((int) (this.value ^ b)) & 0xff] ^ (this.value >>> 8);
        this.value = ~this.value;
    }

    @Override
    public void update(int b) {
        update((byte) (b & 0xFF));
    }

    @Override
    public void update(byte[] b, int off, int len) {
        for (int i = off; len > 0; len--) {
            update(b[i++]);
        }
    }

    @Override
    public void reset() {
        this.value = 0;
    }

    private static final int GF2_DIM = 64; /*
     * dimension of GF(2) vectors (length
     * of CRC)
     */

    private static long gf2MatrixTimes(long[] mat, long vec) {
        long sum = 0;
        int idx = 0;
        while (vec != 0) {
            if ((vec & 1) == 1)
                sum ^= mat[idx];
            vec >>>= 1;
            idx++;
        }
        return sum;
    }

    private static void gf2MatrixSquare(long[] square, long[] mat) {
        for (int n = 0; n < GF2_DIM; n++)
            square[n] = gf2MatrixTimes(mat, mat[n]);
    }

    /*
     * Return the CRC-64 of two sequential blocks, where summ1 is the CRC-64 of
     * the first block, summ2 is the CRC-64 of the second block, and len2 is the
     * length of the second block.
     */
    static public CRC64Checksum combine(CRC64Checksum summ1, CRC64Checksum summ2, long len2) {
        // degenerate case.
        if (len2 == 0)
            return new CRC64Checksum(summ1.getValue());

        int n;
        long row;
        long[] even = new long[GF2_DIM]; // even-power-of-two zeros operator
        long[] odd = new long[GF2_DIM]; // odd-power-of-two zeros operator

        // put operator for one zero bit in odd
        odd[0] = POLY; // CRC-64 polynomial

        row = 1;
        for (n = 1; n < GF2_DIM; n++) {
            odd[n] = row;
            row <<= 1;
        }

        // put operator for two zero bits in even
        gf2MatrixSquare(even, odd);

        // put operator for four zero bits in odd
        gf2MatrixSquare(odd, even);

        // apply len2 zeros to crc1 (first square will put the operator for one
        // zero byte, eight zero bits, in even)
        long crc1 = summ1.getValue();
        long crc2 = summ2.getValue();
        do {
            // apply zeros operator for this bit of len2
            gf2MatrixSquare(even, odd);
            if ((len2 & 1) == 1)
                crc1 = gf2MatrixTimes(even, crc1);
            len2 >>>= 1;

            // if no more bits set, then done
            if (len2 == 0)
                break;

            // another iteration of the loop with odd and even swapped
            gf2MatrixSquare(odd, even);
            if ((len2 & 1) == 1)
                crc1 = gf2MatrixTimes(odd, crc1);
            len2 >>>= 1;

            // if no more bits set, then done
        } while (len2 != 0);

        // return combined crc.
        crc1 ^= crc2;
        return new CRC64Checksum(crc1);
    }

    /*
     * Return the CRC-64 of two sequential blocks, where summ1 is the CRC-64 of
     * the first block, summ2 is the CRC-64 of the second block, and len2 is the
     * length of the second block.
     */
    static public long combine(long crc1, long crc2, long len2) {
        // degenerate case.
        if (len2 == 0)
            return crc1;

        int n;
        long row;
        long[] even = new long[GF2_DIM]; // even-power-of-two zeros operator
        long[] odd = new long[GF2_DIM]; // odd-power-of-two zeros operator

        // put operator for one zero bit in odd
        odd[0] = POLY; // CRC-64 polynomial

        row = 1;
        for (n = 1; n < GF2_DIM; n++) {
            odd[n] = row;
            row <<= 1;
        }

        // put operator for two zero bits in even
        gf2MatrixSquare(even, odd);

        // put operator for four zero bits in odd
        gf2MatrixSquare(odd, even);

        // apply len2 zeros to crc1 (first square will put the operator for one
        // zero byte, eight zero bits, in even)
        do {
            // apply zeros operator for this bit of len2
            gf2MatrixSquare(even, odd);
            if ((len2 & 1) == 1)
                crc1 = gf2MatrixTimes(even, crc1);
            len2 >>>= 1;

            // if no more bits set, then done
            if (len2 == 0)
                break;

            // another iteration of the loop with odd and even swapped
            gf2MatrixSquare(odd, even);
            if ((len2 & 1) == 1)
                crc1 = gf2MatrixTimes(odd, crc1);
            len2 >>>= 1;

            // if no more bits set, then done
        } while (len2 != 0);

        // return combined crc.
        crc1 ^= crc2;
        return crc1;
    }

}