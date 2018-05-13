using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            int x = plainText.Count / 2;
            int[,] pt = new int[2, 1];
            int[,] rowKey = new int[1, 2];
            int[,] key = new int[2, 2];
            int cnt = 0, ind = 0;
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    int[,] ct = new int[1, x];
                    int count;
                    rowKey[0, 0] = i; rowKey[0, 1] = j;
                    ct = GetCT2(rowKey, plainText, x);
                    count = 0;
                    for (int a = 0, b = ind; a < x; a++, b += 2)
                    {
                        if (ct[0, a] == cipherText[b])
                            count++;
                    }
                    if (count == x)
                    {
                        key[cnt, 0] = rowKey[0, 0];
                        key[cnt, 1] = rowKey[0, 1];
                        cnt++;
                        ind++;
                        break;
                    }

                    rowKey[0, 0] = j; rowKey[0, 1] = i;
                    ct = GetCT2(rowKey, plainText, x);
                    count = 0;
                    for (int a = 0, b = ind; a < x; a++, b += 2)
                    {
                        if (ct[0, a] == cipherText[b])
                            count++;
                    }
                    if (count == x)
                    {
                        key[cnt, 0] = rowKey[0, 0];
                        key[cnt, 1] = rowKey[0, 1];
                        cnt++;
                        ind++;
                        break;
                    }
                }
                if (cnt == 2)
                    break;
            }
            if (cnt != 2)
            {
                throw new InvalidAnlysisException();
            }
            List<int> finalList = new List<int>();
            for (int i = 0; i < 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    finalList.Add(key[i, j]);
                }
            }
            return finalList;
        }


        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            List<int> plainText = new List<int>();
            int m = 0;
            if (key.Count == 4)
            {
                m = 2;
            }
            else
            {
                m = 3;
            }

            int[,] k = new int[m, m];
            int[,] invK = new int[m, m];
            int[,] ct = new int[m, 1];
            int cnt = 0;

            //Fill key matrix
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    k[i, j] = key[cnt++];
                }
            }

            int[,] invKey = FindInvKey(k);
            if (invKey.Length == 1)
            {
                throw new Exception();
            }
            for (int i = 0; i < cipherText.Count; i += m)
            {
                for (int j = i, x = 0; j < i + m; j++, x++)
                {
                    ct[x, 0] = cipherText[j];
                }

                int[,] pt = MatrixMutliplication(invKey, ct, m, m, 1);

                for (int a = 0; a < m; a++)
                {
                    plainText.Add(pt[a, 0]);
                }
            }

            return plainText;
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> cipherText = new List<int>();
            int m = 0;
            if (key.Count == 4)
            {
                m = 2;
            }
            else
            {
                m = 3;
            }

            int[,] k = new int[m, m];
            int[,] pt = new int[m, 1];
            int cnt = 0;

            //Fill key matrix
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    k[i, j] = key[cnt++];
                }
            }

            for (int i = 0; i < plainText.Count; i += m)
            {
                for (int j = i, x = 0; j < i + m; j++, x++)
                {
                    pt[x, 0] = plainText[j];
                }

                int[,] ct = MatrixMutliplication(k, pt, m, m, 1);

                for (int a = 0; a < m; a++)
                {
                    cipherText.Add(ct[a, 0]);
                }
            }
            return cipherText;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            int x = plainText.Count / 3;
            int[,] pt = new int[3, 1];
            int[,] rowKey = new int[1, 3];
            int[,] key = new int[3, 3];
            int cnt = 0, ind = 0;
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        int[,] ct = new int[1, x];
                        int count;
                        rowKey[0, 0] = i; rowKey[0, 1] = j; rowKey[0, 2] = k;
                        ct = GetCT(rowKey, plainText, x);
                        count = 0;
                        for (int a = 0, b = ind; a < x; a++, b += 3)
                        {

                            if (ct[0, a] == cipherText[b])
                                count++;
                        }
                        if (count == x)
                        {

                            key[cnt, 0] = rowKey[0, 0];
                            key[cnt, 1] = rowKey[0, 1];
                            key[cnt, 2] = rowKey[0, 2];
                            cnt++;
                            ind++;
                            break;
                        }

                        rowKey[0, 0] = i; rowKey[0, 1] = k; rowKey[0, 2] = j;
                        ct = GetCT(rowKey, plainText, x);
                        count = 0;
                        for (int a = 0, b = ind; a < x; a++, b += 3)
                        {

                            if (ct[0, a] == cipherText[b])
                                count++;
                        }
                        if (count == x)
                        {

                            key[cnt, 0] = rowKey[0, 0];
                            key[cnt, 1] = rowKey[0, 1];
                            key[cnt, 2] = rowKey[0, 2];
                            cnt++;
                            ind++;
                            break;
                        }
                        rowKey[0, 0] = j; rowKey[0, 1] = i; rowKey[0, 2] = k;
                        ct = GetCT(rowKey, plainText, x);
                        count = 0;
                        for (int a = 0, b = ind; a < x; a++, b += 3)
                        {

                            if (ct[0, a] == cipherText[b])
                                count++;
                        }
                        if (count == x)
                        {

                            key[cnt, 0] = rowKey[0, 0];
                            key[cnt, 1] = rowKey[0, 1];
                            key[cnt, 2] = rowKey[0, 2];
                            cnt++;
                            ind++;
                            break;
                        }
                        rowKey[0, 0] = j; rowKey[0, 1] = k; rowKey[0, 2] = i;
                        ct = GetCT(rowKey, plainText, x);
                        count = 0;
                        for (int a = 0, b = ind; a < x; a++, b += 3)
                        {

                            if (ct[0, a] == cipherText[b])
                                count++;
                        }
                        if (count == x)
                        {

                            key[cnt, 0] = rowKey[0, 0];
                            key[cnt, 1] = rowKey[0, 1];
                            key[cnt, 2] = rowKey[0, 2];
                            cnt++;
                            ind++;
                            break;
                        }
                        rowKey[0, 0] = k; rowKey[0, 1] = i; rowKey[0, 2] = i;
                        ct = GetCT(rowKey, plainText, x);
                        count = 0;
                        for (int a = 0, b = ind; a < x; a++, b += 3)
                        {

                            if (ct[0, a] == cipherText[b])
                                count++;
                        }
                        if (count == x)
                        {

                            key[cnt, 0] = rowKey[0, 0];
                            key[cnt, 1] = rowKey[0, 1];
                            key[cnt, 2] = rowKey[0, 2];
                            cnt++;
                            ind++;
                            break;
                        }
                        rowKey[0, 0] = k; rowKey[0, 1] = j; rowKey[0, 2] = i;
                        ct = GetCT(rowKey, plainText, x);
                        count = 0;
                        for (int a = 0, b = ind; a < x; a++, b += 3)
                        {

                            if (ct[0, a] == cipherText[b])
                                count++;
                        }
                        if (count == x)
                        {

                            key[cnt, 0] = rowKey[0, 0];
                            key[cnt, 1] = rowKey[0, 1];
                            key[cnt, 2] = rowKey[0, 2];
                            cnt++;
                            ind++;
                            break;
                        }
                        if (cnt == 3)
                            break;
                    }
                    if (cnt == 3)
                        break;
                }
                if (cnt == 3)
                    break;
            }
            if (cnt != 3)
            {
                throw new InvalidAnlysisException();
            }
            List<int> finalList = new List<int>();
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    finalList.Add(key[i, j]);
                }
            }
            return finalList;
        }

        //Helper functions
        public int[,] MatrixMutliplication(int[,] a, int[,] b, int row1, int col1, int col2)
        {
            int[,] result = new int[row1, col2];

            for (int i = 0; i < row1; i++)
            {
                for (int j = 0; j < col2; j++)
                {
                    for (int x = 0; x < col1; x++)
                    {
                        result[i, j] += (a[i, x] * b[x, j]);
                    }
                    result[i, j] %= 26;
                }
            }
            return result;
        }


        public int[,] GetCT(int[,] rowKey, List<int> plainText, int x)
        {
            int[,] ct = new int[1, x];
            int[,] pt = new int[3, 1];
            for (int z = 0, t = 0; z < plainText.Count; z += 3, t++)
            {
                pt[0, 0] = plainText[z];
                pt[1, 0] = plainText[z + 1];
                pt[2, 0] = plainText[z + 2];
                int[,] res = MatrixMutliplication(rowKey, pt, 1, 3, 1);
                ct[0, t] = res[0, 0];
            }
            return ct;
        }


        public int[,] GetCT2(int[,] rowKey, List<int> plainText, int x)
        {
            int[,] ct = new int[1, x];
            int[,] pt = new int[2, 1];
            for (int z = 0, t = 0; z < plainText.Count; z += 2, t++)
            {
                pt[0, 0] = plainText[z];
                pt[1, 0] = plainText[z + 1];

                int[,] res = MatrixMutliplication(rowKey, pt, 1, 2, 1);
                ct[0, t] = res[0, 0];
            }
            return ct;
        }

        public int[,] FindInvKey(int[,] key)
        {
            int[,] errorMatrix = new int[1, 1];
            int det = FindDet(key);
            if (det > 0)
                det %= 26;
            else
                det = (det % 26) + 26;

            // Check that det and 26 are coprime
            if (GCD(det, 26) != 1)
                return errorMatrix;

            // Get the Modular multiplicative inverse of det(k)
            int b = ModularMultiplicativeInverse(det, 26);
            if (b == -1)
                return errorMatrix;

            // Get the inverse key if the matrix is 2*2
            if (key.Length == 4)
            {
                int x = 1 / (key[0, 0] * key[1,1] - key[0, 1] * key[1, 0]);
                int[,] inv = new int[2, 2];
                inv[0, 0] = (key[1, 1] * x) % 26;
                inv[1, 1] = (key[0, 0] * x) % 26;
                inv[0, 1] = (-1 * key[0, 1] * x) % 26;
                inv[1, 0] = (-1 * key[1, 0] * x) % 26;
                for (int i = 0; i < 2; i++)
                {
                    for (int j = 0; j < 2; j++)
                    {
                        if (inv[i, j] < 0)
                        {
                            inv[i, j] += 26;
                        }
                    }
                }
                return inv;
            }

            // Get the inverse key if the matrix is 3*3
            int[,] invKey = new int[3, 3];

            invKey[0, 0] = (b * (int)Math.Pow((int)-1, (int)0) * ((key[1, 1] * key[2, 2] - key[1, 2] * key[2, 1]) % 26)) % 26;
            invKey[0, 1] = (b * (int)Math.Pow((int)-1, (int)1) * ((key[1, 0] * key[2, 2] - key[1, 2] * key[2, 0]) % 26)) % 26;
            invKey[0, 2] = (b * (int)Math.Pow((int)-1, (int)2) * ((key[1, 0] * key[2, 1] - key[1, 1] * key[2, 0]) % 26)) % 26;

            invKey[1, 0] = (b * (int)Math.Pow((int)-1, (int)1) * ((key[0, 1] * key[2, 2] - key[0, 2] * key[2, 1]) % 26)) % 26;
            invKey[1, 1] = (b * (int)Math.Pow((int)-1, (int)2) * ((key[0, 0] * key[2, 2] - key[0, 2] * key[2, 0]) % 26)) % 26;
            invKey[1, 2] = (b * (int)Math.Pow((int)-1, (int)3) * ((key[0, 0] * key[2, 1] - key[0, 1] * key[2, 0]) % 26)) % 26;

            invKey[2, 0] = (b * (int)Math.Pow((int)-1, (int)2) * ((key[0, 1] * key[1, 2] - key[0, 2] * key[1, 1]) % 26)) % 26;
            invKey[2, 1] = (b * (int)Math.Pow((int)-1, (int)3) * ((key[0, 0] * key[1, 2] - key[0, 2] * key[1, 0]) % 26)) % 26;
            invKey[2, 2] = (b * (int)Math.Pow((int)-1, (int)4) * ((key[0, 0] * key[1, 1] - key[0, 1] * key[1, 0]) % 26)) % 26;

            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    if (invKey[i, j] < 0)
                        invKey[i, j] += 26;
                }
            }

            int[,] finalInvKey = new int[3, 3];
            for (int j = 0; j < 3; j++)
            {
                for (int i = 0; i < 3; i++)
                {
                    finalInvKey[j, i] = invKey[i, j];
                }
            }


            return finalInvKey;
        }


        public int FindDet(int[,] matrix)
        {
            int det = 0;
            if (matrix.Length == 4)
            {
                det = (matrix[0, 0] * matrix[1, 1]) - (matrix[0, 1] * matrix[1, 0]);
            }
            else
            {
                det = matrix[0, 0] * (matrix[1, 1] * matrix[2, 2] - matrix[1, 2] * matrix[2, 1]) - matrix[0, 1] * (matrix[1, 0] * matrix[2, 2] - matrix[1, 2] * matrix[2, 0]) + matrix[0, 2] * (matrix[1, 0] * matrix[2, 1] - matrix[1, 1] * matrix[2, 0]);
            }
            return det;
        }

        public int GCD(int a, int b)
        {
            if (b == 0)
                return a;

            int rem = a % b;
            return GCD(b, rem);
        }


        public int ModularMultiplicativeInverse(int a, int m)
        {
            int b = -1;
            for (int i = 0; i < m; i++)
            {
                if ((i * a) % 26 == 1)
                {
                    return i;
                }
            }
            return b;
        }

    }
}
