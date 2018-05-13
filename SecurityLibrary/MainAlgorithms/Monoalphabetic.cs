using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            char[] key = new char[26];
            for (int i = 0; i < 26; ++i)
            {
                key[i] = '0';
            }
            List<char> c = new List<char>();
            char[] key1 = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            for (int i = 0; i < plainText.Length; ++i)
            {
                key[plainText[i] - 'a'] = (char)(cipherText[i]+32);
                c.Add((char)(cipherText[i]+32));
            }
            int j = 0;
            for (int i = 0; i < 26; ++i)
            {
                if (key[i] == '0')
                {
                    for (; j < 26; ++j)
                    {
                        if (!c.Contains(key1[j]))
                        {
                            key[i] = key1[j];
                            c.Add(key1[j]);
                            break;
                        }
                    }

                }
            }
            return new string (key);
        }

        public string Decrypt(string cipherText, string key)
        {
            string plainText = "";
            for (int i = 0; i < cipherText.Length; ++i)
            {
                int j = 0;
                for (; j < key.Length; ++j) {
                    if ((char)(cipherText[i]+32) == key[j]) break;
                }
                plainText += (char)(j + 'a');

            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            string cipherText = "";
            for (int i = 0; i < plainText.Length; ++i)
            {

                cipherText += key[plainText[i] - 'a'] ;

            }
            return cipherText;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        
            /// S	6.54
        /// R	6.12
        
            /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            string plain = "";
            float[] freq = new float[26];
            Array.Clear(freq, 0, freq.Length);

            //string cipher = "EGSDAMTUMOLHGHFELWADDAUFDUMMEDDVAMIHQELEVOLAOHG".ToUpper();
            foreach (char c in cipher)
            {
                ++freq[c - 'A'] ;

            }
            int s = cipher.Length;
            char[] mp = new char[26];
            for (int i = 0; i < 26; ++i)
            {
                freq[i] /= s;
                if (freq[i] >= 10.8 / 100) mp[i] = 'e';
                else if (freq[i] >= 8.6 / 100) mp[i] = 't';
                else if (freq[i] >= 7.8 / 100) mp[i] = 'a';
                else if (freq[i] >= 7.35 / 100) mp[i] = 'o';
                else if (freq[i] >= 7.175 / 100) mp[i] = 'i';
                else if (freq[i] >= 6.99 / 100) mp[i] = 'n';
                else if (freq[i] >= 6.3 / 100) mp[i] = 's';
                else if (freq[i] >= 5.8 / 100) mp[i] = 'r';
                else if (freq[i] >= 4.7 / 100) mp[i] = 'h';
                else if (freq[i] >= 4.0 / 100) mp[i] = 'l';
                else if (freq[i] >= 3.3 / 100) mp[i] = 'd';
                else if (freq[i] >= 2.9 / 100) mp[i] = 'c';
                else if (freq[i] >= 2.6 / 100) mp[i] = 'u';
                else if (freq[i] >= 2.3 / 100) mp[i] = 'm';
                else if (freq[i] >= 2.1 / 100) mp[i] = 'f';
                else if (freq[i] >= 1.95 / 100) mp[i] = 'p';
                else if (freq[i] >= 1.9 / 100) mp[i] = 'g';
                else if (freq[i] >= 1.75 / 100) mp[i] = 'w';
                else if (freq[i] >= 1.6 / 100) mp[i] = 'y';
                else if (freq[i] >= 1.5 / 100) mp[i] = 'b';
                else if (freq[i] >= .83 / 100) mp[i] = 'v';
                else if (freq[i] >= .43 / 100) mp[i] = 'k';
                else if (freq[i] >= .29 / 100) mp[i] = 'x';
                else if (freq[i] >= .135 / 100) mp[i] = 'j';
                else if (freq[i] >= 0.1 / 100) mp[i] = 'q';
                else mp[i] = 'z';


            }
            foreach (char c in cipher)
            {
                plain += (char)(mp[c - 'A']);

            }


            return plain; 

        }
    }
}
