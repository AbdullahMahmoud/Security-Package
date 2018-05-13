using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string Key = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                Key += (char)(((((cipherText[i] - 'A') - (plainText[i] - 'a')) + 26) % 26) + 'a');
            }
            return FilterTheKey(Key);
        }

        public string Decrypt(string cipherText, string key)
        {
            key = Repeatingkey(cipherText, key);
            string plainText = "";
            for (int i = 0; i < cipherText.Length; ++i)
            {
                plainText += (char)(((((cipherText[i] - 'A') - (key[i] - 'a')) + 26) % 26) + 'a');
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            key = Repeatingkey(plainText, key);
            string cipherText = "";
            for (int i = 0; i < plainText.Length; ++i)
            {
                cipherText += (char)(((((plainText[i] - 'a') + (key[i] - 'a')) % 26) + 'A'));
            }
            return cipherText;
        }
        private string Repeatingkey(string plainText, string key)
        {
            string NewKey = key;
            for (int i = 0; i < plainText.Length - key.Length; i++)
            {
                NewKey += key[i % key.Length];
            }
            return NewKey;
        }
        private string FilterTheKey(string key)
        {
            string ActualKey = "";
            ActualKey += key[0];
            for (int i = 1; i < key.Length; i++)
            {
                int j = i;
                int k = 0;
                for (; j < key.Length; j++, k++)
                {
                    if (key[k % i] != key[j]) break;
                }
                if (j == key.Length) return ActualKey;
                ActualKey += key[i];
            }
            return ActualKey;
        }
    }
}