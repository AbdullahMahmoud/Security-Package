using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            long P = p, Q = q, E = e, m = M;
            long N = P * Q;
            long euler = (P - 1) * (Q - 1);
            long C = pow(m, E, N);

            return (int)C;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            long P = p, Q = q, E = e, c = C;
            long N = P * Q;
            long euler = (P - 1) * (Q - 1);
            int d = GetMultiplicativeInverse(e, (int)euler);
            long M = pow(c, d, N);
            return (int)M;
        }

        //helper functions
        public long pow(long a, long n, long mod)
        {
            long res = 1;
            a = a % mod;
            while (n > 0)
            {
                res = (res * a) % mod;
                n--;
            }
            return res;
        }

        public int GetMultiplicativeInverse(int number, int baseN)
        {
            int b = -1;
            for (int i = 0; i < baseN; i++)
            {
                long I = i, n = number;
                long x = I * n;
                if (x % baseN == 1)
                {
                    return i;
                }
            }
            return b;
        }


    }
}