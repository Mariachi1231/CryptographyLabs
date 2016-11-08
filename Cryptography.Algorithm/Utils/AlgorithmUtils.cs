using System.Linq;
using System.Text;

namespace Cryptography.Algorithm.Utils
{
    public static class AlgorithmUtils
    {
        internal static bool IsCanDivideBy(string source, int devisor)
        {
            return source.ToByteArray().ToBits().Count() % devisor == 0;
        }

        internal static string AddHiddenInformation(string source, int blockSizeInBytes)
        {
            StringBuilder sb = new StringBuilder(source);
            int lack = blockSizeInBytes - (source.Length % blockSizeInBytes);
            for (int i = 0; i < lack; i++)
                sb.Append(" ");

            return sb.ToString();
        }

        internal static void Swap(ref bool[] left, ref bool[] right)
        {
            var temp = left.ToArray();
            left = right.ToArray();
            right = temp;
        }
    }
}