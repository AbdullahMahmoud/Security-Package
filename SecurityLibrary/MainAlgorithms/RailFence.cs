using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int key = 2;
            for (; key < plainText.Length; key++)
            {
                if (Encrypt(plainText, key) == cipherText) break;
            }
            return key;
        }

        public string Decrypt(string cipherText, int key)
        {
            int ColumnLength = (cipherText.Length + (key - 1)) / key;
            int NumOfExtras = cipherText.Length % key;
            string plainText = "";
            for (int i = 0; i < ColumnLength; i++)
            {
                if (i + 1 != ColumnLength || NumOfExtras == 0)
                {
                    for (int j = 0; j < key; j++)
                    {
                        plainText += cipherText[j * ColumnLength - ((NumOfExtras != 0 && j > NumOfExtras) ? 1 : 0) * (j - NumOfExtras) + i];
                    }
                }
                else
                {
                    for (int j = 0; j < NumOfExtras; j++)
                    {
                        plainText += cipherText[j * ColumnLength - ((NumOfExtras != 0 && j > NumOfExtras) ? 1 : 0) * (j - NumOfExtras) + i];
                    }
                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, int key)
        {
            string cipherText = "";
            for (int i = 0; i < key; i++)
            {
                for (int j = i; j < plainText.Length; j += key)
                {
                    cipherText += plainText[j];
                }
            }
            return cipherText;
        }
    }
}
