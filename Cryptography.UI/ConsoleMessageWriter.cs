using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cryptography.Infostructure;

namespace Cryptography.UI
{
    public class ConsoleMessageWriter : IMessageWriter
    {
        public ConsoleMessageWriter()
        {
        }

        public void WriteMessage(string message)
        {
            Console.WriteLine(message);
        }
    }
}
