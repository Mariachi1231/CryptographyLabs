using System;
using System.Linq;
using System.Text;
using System.Threading;
using Microsoft.SqlServer.Server;

namespace Cryptography.Algorithm.Utils
{
    public static class AlgorithmUtils
    {
        internal static bool IsCanDivideByBits(string source, int devisorInBits)
        {
            return source.ToByteArray().ToBits().Count() % devisorInBits == 0;
        }

        internal static bool IsCanDivideByBytes(string source, int devisorInBytes)
        {
            return source.ToByteArray().Count() % devisorInBytes == 0;
        }

        internal static string AddHiddenInformation(string source, int blockSizeInBytes)
        {
            StringBuilder sb = new StringBuilder(source);
            int lack = blockSizeInBytes - (source.Length % blockSizeInBytes);
            for (int i = 0; i < lack; i++)
                sb.Append(" ");

            return sb.ToString();
        }

        internal static bool[] GenerateRadomSequence(uint size)
        {
            Random rand = new Random();
            bool[] array = new bool[size];

            for (int i = 0; i < size; i++)
            {
                array[i] = rand.Next(0, 2) == 1;
                Thread.Sleep(15);
            }

            return array;
        }

        internal static void Swap(ref bool[] left, ref bool[] right)
        {
            var temp = left.ToArray();
            left = right.ToArray();
            right = temp;
        }
    }
}