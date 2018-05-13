using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>

        public long Pow(int Num, int Pow, int Mod)
        {
            long res = Num;

            for (int i = 2; i <= Pow; i++)
            {
                res *= (Num);
                res %= Mod;
            }
            return res;

        }
        public int inv_mod(int Num, int Mod)
        {
            int res = 0;
            for (int i = 0; i < Mod; i++)
                if ((Num * i) % Mod == 1)
                    res = i;
            return res;
        }
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            List<long> res = new List<long>();

            long C1 = Pow(alpha, k, q);
            long K = Pow(y, k, q);
            long C2 = (K * m) % q;
            res.Add(C1);
            res.Add(C2);
            return res;


        }
        public int Decrypt(int c1, int c2, int x, int q)
        {

            int k = (int)(Pow(c1, x, q));
            int k_inv = inv_mod(k, q);
            int M = (c2 * k_inv) % q;
            return M;

        }
    }
}
