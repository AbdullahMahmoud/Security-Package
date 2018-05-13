using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        public string Decrypt(string cipherText, List<string> key)
        {
            DES TripleDes = new DES();
            string A = TripleDes.Decrypt(cipherText, key[0]);
            string B = TripleDes.Encrypt(A, key[1]);
            string C = TripleDes.Decrypt(B, key[0]);
            return C;
        }

        public string Encrypt(string plainText, List<string> key)
        {
            DES TripleDes = new DES();
            string A = TripleDes.Encrypt(plainText, key[0]);
            string B = TripleDes.Decrypt(A, key[1]);
            string C = TripleDes.Encrypt(B, key[0]);
            return C;
        }

        public List<string> Analyse(string plainText,string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}
