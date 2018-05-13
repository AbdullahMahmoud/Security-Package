using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        public int[] PC1 =
        {
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
        };
        public int[] PC2 =
       {
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
        };
        public int[] E =
       {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
        };

        public int[] P =
        {
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25
        };
        public static int[] IP =
       {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        };

        public static int[] IPINV =
        {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
        };
        public byte[,] SBoxes =
        {
            {
                14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
            },
            {
                15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
            },
            {
                10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
                13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
                1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
            },
            {
                7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
                13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
                10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
                3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
            },
            {
                2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
            },
            {
                12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
            },
            {
                4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
            },
            {
                13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
                1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
                7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
                2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
            }
};
        private int[] ShiftAmount = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

        private BitArray ShiftLeft(BitArray bits, int round)
        {
            BitArray ci_1 = new BitArray(28);
            BitArray di_1 = new BitArray(28);
            for (int i = 0; i < 28; ++i)
            {
                ci_1[i] = bits[i];
                di_1[i] = bits[i + 28];
            }
            int amount = ShiftAmount[round];
            BitArray ShiftedBits = new BitArray(ci_1.Length);
            BitArray ShiftedBits1 = new BitArray(di_1.Length);

            for (int i = 0; i < ci_1.Length; i++)
            {
                if (i + amount >= ci_1.Length)
                {
                    ShiftedBits[i] = ci_1[(i + amount) - ci_1.Length];
                    ShiftedBits1[i] = di_1[(i + amount) - di_1.Length];
                }
                else
                {
                    ShiftedBits[i] = ci_1[i + amount];
                    ShiftedBits1[i] = di_1[i + amount];
                }
            }
            BitArray nShiftedBits = new BitArray(56);
            for (int i = 0; i < 28; ++i)
            {
                nShiftedBits[i] = ShiftedBits[i];
            }
            for (int i = 0; i < 28; ++i)
            {
                nShiftedBits[i + 28] = ShiftedBits1[i];
            }
            return nShiftedBits;
        }
        private BitArray applyPermution(BitArray R)
        {

            BitArray nR = new BitArray(32);

            for (int i = 0; i < 32; ++i)
            {
                nR[i] = R[P[i] - 1];
            }
            // Console.WriteLine(ToBitString(nkey));
            //Console.WriteLine(ToBitString(bits));


            return nR;
        }

        private BitArray applyExpansion(BitArray R)
        {
            BitArray nR = new BitArray(48);
            for (int i = 0; i < 48; ++i)
            {
                nR[i] = R[E[i] - 1];
            }
            return nR;
        }
        private BitArray applyPermutedChoice1(BitArray key)
        {

            BitArray nkey = new BitArray(56);

            for (int i = 0; i < 56; ++i)
            {
                nkey[i] = key[PC1[i] - 1];
            }
            // Console.WriteLine(ToBitString(nkey));
            //Console.WriteLine(ToBitString(bits));


            return nkey;
        }
        private BitArray applyPermutedChoice2(BitArray key)
        {

            BitArray nkey = new BitArray(48);

            for (int i = 0; i < 48; ++i)
            {
                nkey[i] = key[PC2[i] - 1];
            }
            // Console.WriteLine(ToBitString(nkey));
            //Console.WriteLine(ToBitString(bits));


            return nkey;
        }
        private byte[] StringToBytes(string HexStr)
        {
            string str = HexStr.Substring(2, HexStr.Length - 2);
            byte[] Bytes = Enumerable.Range(0, str.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(str.Substring(x, 2), 16))
                             .ToArray();
            return Bytes;
        }
        private BitArray applysubstitution(BitArray R)
        {
            BitArray tmp = new BitArray(2);
            BitArray tmp1 = new BitArray(4);
            BitArray newR = new BitArray(32);
            int count = 0;
            for (int i = 0; i < 48; i += 6)
            {
                tmp[0] = R[i + 5]; tmp[1] = R[i];
                int[] integer = new int[1]; tmp.CopyTo(integer, 0);
                tmp1[0] = R[i + 4];
                tmp1[1] = R[i + 3];
                tmp1[2] = R[i + 2];
                tmp1[3] = R[i + 1];
                int[] integer1 = new int[1]; tmp1.CopyTo(integer1, 0);
                byte t = SBoxes[i / 6, integer[0] * 16 + integer1[0]];
                BitArray bits = new BitArray(BitConverter.GetBytes(t).ToArray());

                for (int j = 0; j < 4; ++j)
                {
                    newR[count] = bits[3 - j];
                    count++;
                }
            }
            return newR;
        }
        private BitArray round_i(BitArray plain_text_round, BitArray key_round)
        {
            BitArray Li_1 = new BitArray(32);
            BitArray Ri_1 = new BitArray(32);
            BitArray Li = new BitArray(32);
            BitArray Ri = new BitArray(32);
            for (int i = 0; i < 32; ++i)
            {
                Li_1[i] = plain_text_round[i];
                Ri_1[i] = plain_text_round[i + 32];
            }
            Li = Ri_1;
            BitArray R = new BitArray(48);
            R = applyExpansion(Ri_1);
            R.Xor(key_round);
            Ri = applysubstitution(R);
            Ri = applyPermution(Ri);
            Ri.Xor(Li_1);

            BitArray plain_text_i_1 = new BitArray(64);
            for (int i = 0; i < 32; ++i)
            {
                plain_text_i_1[i] = Li[i];
            }
            for (int i = 0; i < 32; ++i)
            {
                plain_text_i_1[i + 32] = Ri[i];
            }
            return plain_text_i_1;
        }
        private string ToBitString(BitArray bits)
        {
            var sb = new StringBuilder();

            for (int i = 0; i < bits.Count; i++)
            {
                char c = bits[i] ? '1' : '0';
                sb.Append(c);
            }

            return sb.ToString();
        }

        public static BitArray hexStringToBits(string str)
        {
            string hex_string = str.Substring(2, str.Length - 2);
            BitArray bits = new BitArray(4 * hex_string.Length);
            for (int i = 0; i < hex_string.Length; i++)
            {
                byte byt = byte.Parse(hex_string[i].ToString(), NumberStyles.HexNumber);
                for (int j = 0; j < 4; j++)
                {
                    bits.Set(i * 4 + j, (byt & (1 << (3 - j))) != 0);
                }
            }
            return bits;
        }


        public override string Decrypt(string cipherText, string key)
        {
            BitArray nkey = hexStringToBits(key);
            BitArray nPlainText = hexStringToBits(cipherText);
            BitArray newPlainText = applyInitialPermutation(nPlainText);
            BitArray permutedArray;
            BitArray shiftedArray = applyPermutedChoice1(nkey);
            for (int i = 15; i >= 0; i--)
            {
                shiftedArray = applyPermutedChoice1(nkey);
                for (int j = 0; j <= i; j++)
                {
                    shiftedArray = ShiftLeft(shiftedArray, j);
                }
                permutedArray = applyPermutedChoice2(shiftedArray);
                newPlainText = round_i(newPlainText, permutedArray);

            }
            newPlainText = applaySwapBits(newPlainText);
            newPlainText = applyInversePermutation(newPlainText);
            return BitArrayToHex(newPlainText);
        }

        public override string Encrypt(string plainText, string key)
        {
            BitArray nkey = hexStringToBits(key);
            BitArray nPlainText = hexStringToBits(plainText);
            BitArray newPlainText = applyInitialPermutation(nPlainText);
            BitArray permutedArray;
            BitArray shiftedArray = applyPermutedChoice1(nkey);
            for (int i = 0; i < 16; ++i)
            {
                shiftedArray = ShiftLeft(shiftedArray, i);
                permutedArray = applyPermutedChoice2(shiftedArray);
                newPlainText = round_i(newPlainText, permutedArray);

            }
            newPlainText = applaySwapBits(newPlainText);
            newPlainText = applyInversePermutation(newPlainText);
            return BitArrayToHex(newPlainText);
            //  BitArray t = applyPermutedChoice1(hexStringToBits("0x133457799BBCDFF1")); ;

        }
        private BitArray applyInitialPermutation(BitArray newPlainText)
        {
            BitArray nR = new BitArray(64);

            for (int i = 0; i < 64; ++i)
            {
                nR[i] = newPlainText[IP[i] - 1];
            }
            // Console.WriteLine(ToBitString(nkey));
            //Console.WriteLine(ToBitString(bits));


            return nR;
        }

        private BitArray applyInversePermutation(BitArray newPlainText)
        {
            BitArray nR = new BitArray(64);

            for (int i = 0; i < 64; ++i)
            {
                nR[i] = newPlainText[IPINV[i] - 1];
            }
            // Console.WriteLine(ToBitString(nkey));
            //Console.WriteLine(ToBitString(bits));


            return nR;
        }
        private string BitArrayToHex(BitArray BitsArray)
        {
            StringBuilder SBuilder = new StringBuilder(BitsArray.Length / 4);

            for (int i = 0; i < BitsArray.Length; i += 4)
            {
                int Value = (BitsArray[i] ? 8 : 0) |
                        (BitsArray[i + 1] ? 4 : 0) |
                        (BitsArray[i + 2] ? 2 : 0) |
                        (BitsArray[i + 3] ? 1 : 0);

                SBuilder.Append(Value.ToString("x1"));
            }
            return "0x" + SBuilder.ToString();
        }
        private BitArray applaySwapBits(BitArray newPlainText)
        {
            BitArray Li_1 = new BitArray(32);
            BitArray Ri_1 = new BitArray(32);

            for (int i = 0; i < 32; ++i)
            {
                Li_1[i] = newPlainText[i];
                Ri_1[i] = newPlainText[i + 32];
            }
            for (int i = 0; i < 32; ++i)
            {
                newPlainText[i] = Ri_1[i];
                newPlainText[i + 32] = Li_1[i];
            }
            return newPlainText;
        }
    }
}
