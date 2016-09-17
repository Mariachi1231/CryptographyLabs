using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Cryptography.Algorithm.Utils
{
    internal static class LocalExtensions
    {
        internal static string[] IndexOfAll<T>(this T[,] array, T value)
            where T : struct
        {
            List<string> items = new List<string>();

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < array.GetLength(0); i++)
                for (int j = 0; j < array.GetLength(1); j++)
                    if (array[i, j].Equals(value))
                    {
                        if (i < 10)
                            sb.Append("0").Append(i);
                        else sb.Append(i);

                        if (j < 10)
                            sb.Append("0").Append(j);
                        else sb.Append(j);

                        items.Add(sb.ToString());
                        sb.Clear();
                    }

            return items.ToArray();
        }

        internal static string RandomString(this string[] strings)
        {
            Random rand = new Random();
            Thread.Sleep(15);
            return strings[rand.Next(strings.Count() - 1)];
        }
    }
}
