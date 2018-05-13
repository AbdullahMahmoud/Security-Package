using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
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
