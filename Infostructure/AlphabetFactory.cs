using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace Cryptography.Infostructure
{
    // TODO     Remove hard coupling.
    // TODO     Add alphabet loading from path in the configuration file.
    public enum AlphabetType
    {
        Roman, 
        Cyrillic
    }
    public static class AlphabetFactory
    {
        public static string TakeAlphabet(AlphabetType alphabetType)
        {
            string alphabet = default(string);

            var path = $"{Environment.CurrentDirectory}\\" + (alphabetType == AlphabetType.Roman ? "romania.txt" : "cyrillic.txt");

            // First initialization
            if (!File.Exists(path))
            {
                switch (alphabetType)
                {
                    case AlphabetType.Roman:
                        alphabet = "abcdefghijklmnopqrstuvwxyz";
                        break;
                    case AlphabetType.Cyrillic:
                        alphabet = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя";
                        break;
                    default:
                        break;
                }

                using (var sw = new StreamWriter(File.Create(path)))
                    sw.Write(alphabet);
            }

            using (var sr = new StreamReader(path))
                alphabet = sr.ReadToEnd();

            return alphabet;
        }
    }
}
