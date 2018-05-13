using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {



        public List<int> Analyse(string plainText, string cipherText)
        {

            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            List<int> Res = new List<int>();

            for (int N = 2; N < plainText.Length; N++)
            {

                int Row = plainText.Length / N;

                if (plainText.Length % N >= 1)
                    Row += 1;

                int Numx = (Row * N) - cipherText.Length;

                if (Numx > N)
                    continue;



                char[,] arr = new char[Row, N];
                char[,] Dec = new char[Row, N];

                int ind = 0;

                for (int i = 0; i < Row; i++)
                {
                    for (int j = 0; j < N; j++)
                    {

                        if (ind >= plainText.Length)
                            arr[i, j] = 'x';

                        else
                            arr[i, j] = plainText[ind++];

                    }

                }

                ind = 0;

                Dictionary<string, int> Mp = new Dictionary<string, int>();

                string A = "";

                for (int j = N - 1 - Numx + 1; j < N; j++)
                    Dec[Row - 1, j] = 'x';




                for (int j = 0; j < N; j++)
                {
                    for (int i = 0; i < Row; i++)
                    {

                        if (Dec[i, j] == 'x')
                            A += 'x';

                        else
                        {
                            Dec[i, j] = cipherText[ind++];

                            A += Dec[i, j];

                        }


                    }

                    Mp[A] = j + 1;
                    A = "";


                }




                List<int> Temp = new List<int>();

                for (int j = 0; j < N; j++)
                {
                    string str = "";

                    for (int i = 0; i < Row; i++)
                    {
                        str += arr[i, j];
                    }

                    if (Mp.ContainsKey(str))
                        Temp.Add(Mp[str]);

                }


                if (Temp.Count == N)
                {
                    Res = Temp;

                    break;
                }
            }
            return Res;
        }

        public string Decrypt(string cipherText, List<int> key)
        {

            int Row = cipherText.Length / key.Count;


            char[,] arr = new char[Row, key.Count];

            for (int i = 0; i < key.Count; i++)
            {
                int ind = (key[i] - 1) * Row;
                int j = 0;

                while (j < Row)
                {
                    arr[j++, i] = cipherText[ind++];
                }

            }

            string res = "";

            for (int i = 0; i < Row; i++)
            {
                for (int j = 0; j < key.Count; j++)
                {
                    res += arr[i, j];
                }

            }

            return res;


        }

        public string Encrypt(string plainText, List<int> key)
        {

            int Row = plainText.Length / key.Count;

            if (plainText.Length % key.Count >= 1)
                Row += 1;

            char[,] arr = new char[Row, key.Count];

            int ind = 0;

            for (int i = 0; i < Row; i++)
            {
                for (int j = 0; j < key.Count; j++)
                {

                    if (ind >= plainText.Length)
                        arr[i, j] = 'x';

                    else
                        arr[i, j] = plainText[ind++];

                }

            }

            Dictionary<int, string> Mp = new Dictionary<int, string>();

            for (int j = 0; j < key.Count; j++)
            {
                string str = "";

                for (int i = 0; i < Row; i++)
                {
                    str += arr[i, j];

                }

                Mp.Add(key[j], str);
            }

            string res = "";

            for (int i = 1; i <= key.Count; i++)
            {
                res += Mp[i];
            }
            return res;

        }
    }
}
