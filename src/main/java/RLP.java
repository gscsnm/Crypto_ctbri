/*
 * Copyright (c) [2016] [ <ether.camp> ]
 * This file is part of the ethereumJ library.
 *
 * The ethereumJ library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The ethereumJ library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the ethereumJ library. If not, see <http://www.gnu.org/licenses/>.
 */
package main.java;

import java.util.*;

import static main.java.ByteUtil.*;

/**
 * Recursive Length Prefix (RLP) encoding.
 * <p>
 * The purpose of RLP is to encode arbitrarily nested arrays of binary data, and
 * RLP is the main encoding method used to serialize objects in Ethereum. The
 * only purpose of RLP is to encode structure; encoding specific atomic data
 * types (eg. strings, integers, floats) is left up to higher-order protocols; in
 * Ethereum the standard is that integers are represented in big endian binary
 * form. If one wishes to use RLP to encode a dictionary, the two suggested
 * canonical forms are to either use [[k1,v1],[k2,v2]...] with keys in
 * lexicographic order or to use the higher-level Patricia Tree encoding as
 * Ethereum does.
 * <p>
 * The RLP encoding function takes in an item. An item is defined as follows:
 * <p>
 * - A string (ie. byte array) is an item - A list of items is an item
 * <p>
 * For example, an empty string is an item, as is the string containing the word
 * "cat", a list containing any number of strings, as well as more complex data
 * structures like ["cat",["puppy","cow"],"horse",[[]],"pig",[""],"sheep"]. Note
 * that in the context of the rest of this article, "string" will be used as a
 * synonym for "a certain number of bytes of binary data"; no special encodings
 * are used and no knowledge about the content of the strings is implied.
 * <p>
 * See: https://github.com/ethereum/wiki/wiki/%5BEnglish%5D-RLP
 *
 * @author Roman Mandeleil
 * @since 01.04.2014
 */
public class RLP {


    private static final int SIZE_THRESHOLD = 56;
    private static final int OFFSET_SHORT_ITEM = 0x80;
    private static final int OFFSET_LONG_ITEM = 0xb7;

    public static byte[] encodeElement(byte[] srcData) {

        // [0x80]
        if (isNullOrZeroArray(srcData)) {
            return new byte[]{(byte) OFFSET_SHORT_ITEM};

        // [0x00]
        } else if (isSingleZero(srcData)) {
            return srcData;

        // [0x01, 0x7f] - single byte, that byte is its own RLP encoding
        } else if (srcData.length == 1 && (srcData[0] & 0xFF) < 0x80) {
            return srcData;

        // [0x80, 0xb7], 0 - 55 bytes
        } else if (srcData.length < SIZE_THRESHOLD) {
            // length = 8X
            byte length = (byte) (OFFSET_SHORT_ITEM + srcData.length);
            byte[] data = Arrays.copyOf(srcData, srcData.length + 1);
            System.arraycopy(data, 0, data, 1, srcData.length);
            data[0] = length;

            return data;
        // [0xb8, 0xbf], 56+ bytes
        } else {
            // length of length = BX
            // prefix = [BX, [length]]
            int tmpLength = srcData.length;
            byte lengthOfLength = 0;
            while (tmpLength != 0) {
                ++lengthOfLength;
                tmpLength = tmpLength >> 8;
            }

            // set length Of length at first byte
            byte[] data = new byte[1 + lengthOfLength + srcData.length];
            data[0] = (byte) (OFFSET_LONG_ITEM + lengthOfLength);

            // copy length after first byte
            tmpLength = srcData.length;
            for (int i = lengthOfLength; i > 0; --i) {
                data[i] = (byte) (tmpLength & 0xFF);
                tmpLength = tmpLength >> 8;
            }

            // at last copy the number bytes after its length
            System.arraycopy(srcData, 0, data, 1 + lengthOfLength, srcData.length);

            return data;
        }
    }

}
