using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography.Infostructure
{
    public interface IKeyGenerator
    {
        string GenerateKey(string additionalInformation = null, string secret = null);

        string GenerateAdditionalInformation(string secret = null);
    }
}
