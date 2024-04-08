using System.IO;
using System.Threading.Tasks;

namespace PgpCore.Extensions
{
    internal static class StreamExtensions
    {
        internal static string GetString(this Stream inputStream)
        {
            var reader = new StreamReader(inputStream);
            var output = reader.ReadToEnd();
            return output;
        }

        internal static async Task<string> GetStringAsync(this Stream inputStream)
        {
            var reader = new StreamReader(inputStream);
            var output = await reader.ReadToEndAsync();
            return output;
        }
    }
}