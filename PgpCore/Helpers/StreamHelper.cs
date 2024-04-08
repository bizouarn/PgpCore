using System.IO;
using System.Threading.Tasks;

namespace PgpCore.Helpers
{
    public static class StreamHelper
    {
        private const int _bufferSize = 512;

        public static void PipeAll(Stream inStr, Stream outStr)
        {
            inStr.CopyTo(outStr, _bufferSize);
        }

        public static Task PipeAllAsync(Stream inStr, Stream outStr)
        {
            return inStr.CopyToAsync(outStr, _bufferSize);
        }
    }
}