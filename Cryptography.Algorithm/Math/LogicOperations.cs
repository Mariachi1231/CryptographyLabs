namespace Cryptography.Algorithm.Math
{
    public static class LogicOperations
    {
        public static uint LeftRotation(uint source, int offset)
        {
            return (((source) << (offset)) | ((source) >> (32 - (offset))));
        }
    }
}