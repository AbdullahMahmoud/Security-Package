using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        public string dec(string cipherText, char[,] matrix)
        {
            string plainText = "";
            int x1 = 0, x2 = 0, y1 = 0, y2 = 0;
            for (int q = 0; q < cipherText.Length; q += 2)
            {
                for (int i = 0; i < 5; ++i)
                {
                    for (int j = 0; j < 5; ++j)
                    {
                        if (matrix[i, j] == (char)(cipherText[q] + 32))
                        {
                            x1 = i;
                            y1 = j;
                        }
                        if (matrix[i, j] == (char)(cipherText[q + 1] + 32))
                        {
                            x2 = i;
                            y2 = j;
                        }
                    }
                }
                if (x1 == x2)
                {
                    plainText += (char)(matrix[x1, ((y1 - 1) + 5) % 5]);
                    plainText += (char)(matrix[x2, ((y2 - 1) + 5) % 5]);
                }
                else if (y1 == y2)
                {
                    plainText += (char)(matrix[((x1 - 1) + 5) % 5, y1]);
                    plainText += (char)(matrix[((x2 - 1) + 5) % 5, y2]);
                }
                else
                {

                    plainText += (char)(matrix[x1, y2]);
                    plainText += (char)(matrix[x2, y1]);

                }



            }
            return plainText;
        }
        public string modifyCipherText(string cipherText) {
            string res = "";
            for (int i = 0; i < cipherText.Length - 2; i += 2)
            {
                if (cipherText[i] == cipherText[i + 2] && cipherText[i + 1] == 'x')
                {
                    res += cipherText[i];
                }
                else
                {
                    res += cipherText[i];
                    res += cipherText[i + 1];
                }
            }
            if (cipherText[cipherText.Length - 1] == 'x')
                res += cipherText[cipherText.Length - 2];
            else
            {
                res += cipherText[cipherText.Length - 2];
                res += cipherText[cipherText.Length - 1];
            }

            return res;
            
        }
        public string Decrypt(string cipherText, string key)
        {
            char[,] matrix = new char[5, 5];
            matrix = fillMatrix(key);
            string s = dec(cipherText, matrix);
            s = modifyCipherText(s); 
            return s;
        }

        public char[,] fillMatrix(string key) {


            char[] chars = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };



            key = key.Replace('j', 'i');
            char[,] matrix = new char[5, 5];
            List<char> c = new List<char>();
            int k = 0, t = 0;
            for (int i = 0; i < 5; ++i)
            {
                for (int j = 0; j < 5; ++j)
                {
                    if (k < key.Length)
                    {
                        for (; k < key.Length; ++k)
                        {
                            if (!c.Contains(key[k]))
                            {
                                matrix[i, j] = key[k];
                                c.Add(key[k]);
                                break;
                            }

                        }
                    }
                    if (matrix[i, j] == '\0')
                    {
                        for (; t < 25; ++t)
                        {
                            if (!c.Contains(chars[t]))
                            {
                                matrix[i, j] = chars[t];
                                c.Add(chars[t]);
                                break;
                            }
                        }

                    }

                }

            }




            /*
                        for (int i = 0; i < 5; ++i)
                        {
                            for (int j = 0; j < 5; ++j)
                            {
                                Console.Write(matrix[i, j]);
                                Console.Write(" ");
                            }
                            Console.WriteLine(" ");

                        }

                */
            return matrix;
        }

        public string modifyPlainText(string plainText) {

            plainText = plainText.Replace('j', 'i');
            for (int i = 0; i < plainText.Length-1; i+=2) {
                if (plainText[i] == plainText[i + 1]) {
                    if(plainText[i]!='x')
                        plainText = plainText.Insert(i + 1, "x");
                    else 
                       plainText = plainText.Insert(i + 1, "y");
                }
            }
            if (plainText.Length % 2 == 1) {
                if (plainText[plainText.Length - 1] != 'x')
                    plainText += 'x';
                else plainText += 'y';
            }
            return plainText;
        }

        public string enc(string plainText, char[,] matrix) {
            string cipherText = "";
            int x1=0, x2=0, y1=0, y2=0;
            for (int q = 0; q < plainText.Length; q += 2) {
                for (int i = 0; i < 5; ++i)
                {
                    for (int j = 0; j < 5; ++j)
                    {
                        if (matrix[i, j] == plainText[q])
                        {
                            x1 = i;
                            y1 = j;
                        }
                        if (matrix[i, j] == plainText[q+1])
                        {
                            x2 = i;
                            y2 = j;
                        }
                    }
                }
                if (x1 == x2)
                {
                    cipherText += (char)(matrix[x1, (y1 + 1) % 5] - 32);
                    cipherText += (char)(matrix[x2, (y2 + 1) % 5] - 32);
                }
                else if (y1 == y2) {
                    cipherText += (char)(matrix[(x1+1)%5, y1 ] - 32);
                    cipherText += (char)(matrix[(x2 + 1) % 5, y2] - 32);
                }
                else {

                    cipherText += (char)(matrix[x1, y2] - 32);
                    cipherText += (char)(matrix[x2, y1] - 32);

                }



                  }
            return cipherText;
        }
        public string Encrypt(string plainText, string key)
        {
            //string cipherText = "";
           
            char[,] matrix = new char[5,5];
            matrix = fillMatrix(key);
            plainText = modifyPlainText(plainText);


            return enc(plainText,matrix);

        }
        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }
    }
}
