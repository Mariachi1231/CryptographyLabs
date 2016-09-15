using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography.Infostructure
{
    public interface IMessageWriter
    {
        void WriteMessage(string message);
    }
}
