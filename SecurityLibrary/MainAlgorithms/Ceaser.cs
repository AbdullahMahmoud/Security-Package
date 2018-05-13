using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            string cipherText="";
            for (int i = 0; i < plainText.Length; ++i) {

                cipherText += (char)(((((plainText[i] - 'a') + key) % 26) + 'A'));

            }
            return cipherText;
        }

        public string Decrypt(string cipherText, int key)
        {
            string plainText = "";
            for (int i = 0; i < cipherText.Length; ++i)
            {
                plainText += (char)(((((cipherText[i] - 'A') - key) + 26) % 26) + 'a');

            }
            return plainText;
        }

        public int Analyse(string plainText, string cipherText)
        {
            int key = (((cipherText[0]-'A') - (plainText[0]-'a')) + 26) % 26;
            return key;
        }
    }
}
