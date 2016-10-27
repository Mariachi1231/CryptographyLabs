namespace Cryptography.Infostructure
{
    public interface ICryptoAlgorithmSettableKey : ICryptoAlgorithm
    {
        void SetKey(string key);
    }
}