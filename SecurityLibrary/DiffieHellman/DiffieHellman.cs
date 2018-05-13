using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            List<int> sec = new List<int>();
            long ya = pow(alpha, xa, q);
            long yb = pow(alpha, xb, q);
            sec.Add((int)pow(yb, xa, q));
            sec.Add((int)pow(ya, xb, q));
            return sec;
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
    }
}