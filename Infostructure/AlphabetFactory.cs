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
            var path = $"{Environment.CurrentDirectory}\\" + (alphabetType == AlphabetType.Roman ? "romania.txt" : "cyrillic.txt");

            // First initialization
            if (!File.Exists(path))
            {
                string content = default(string);
                switch (alphabetType)
                {
                    case AlphabetType.Roman:
                        content = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
                        break;
                    case AlphabetType.Cyrillic:
                        content = "абвгдеёжзийклмнопрстуфхцчшщъыьэюяАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";
                        break;
                    default:
                        break;
                }

                using (var sw = new StreamWriter(File.Create(path)))
                    sw.Write(content);
            }

            return TakeAlphabetFromFile(path);
        }

        public static string TakeAlphabetFromFile(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                throw new ArgumentNullException("Invalid path to alphabet.");

            string alphabet = default(string);
            using (var sr = new StreamReader(path))
                alphabet = sr.ReadToEnd();

            return alphabet.ToLowerInvariant();
        }
    }
}
