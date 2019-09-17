using Microsoft.Extensions.Logging;
using System;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;

namespace CheckPasswordStrength
{
    public class DeterminePwnedService : IDeterminePwnedService
    {

        private readonly IHttpClientFactory _clientFactory;
        private readonly ILogger<DeterminePwnedService> _logger;

        public DeterminePwnedService(IHttpClientFactory clientFactory, ILogger<DeterminePwnedService> logger)
        {
            _clientFactory = clientFactory;
            _logger = logger;
        }

        /// <summary>
        /// Compute SHA1 of the password and check if password is pwned by passing first 5 char of hash to api.pwnedpasswords.com
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        public async Task<long> CheckIfPwned(string password)
        {

            var sha1ofPassword = UtilCryptoSHA1.SHA1HashForPassword(password);
            var prefixofSha1 = sha1ofPassword.Substring(0, 5);
            var suffixofSha1 = sha1ofPassword.Substring(5);

            var request = new HttpRequestMessage(HttpMethod.Get, "https://api.pwnedpasswords.com/range/" + prefixofSha1);
            var client = _clientFactory.CreateClient();
            try
            {
                var response = await client.SendAsync(request);

                if (response.IsSuccessStatusCode)
                {
                    _logger.LogDebug("SuccessStatus code received for http request to https://api.pwnedpasswords.com ");
                    var PwnedFrequency = await Contains(response.Content, suffixofSha1);
                    var PwnedCount = (PwnedFrequency >= 1);
                    return PwnedFrequency;

                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error calling the pwnedpasswords api");
            }
            return 0;
        }

        /// <summary>
        /// Analyze the response to find the pwned frequency of password. 
        /// </summary>
        /// <param name="content"></param>
        /// <param name="suffixofSha1"></param>
        /// <returns></returns>
        internal static async Task<long> Contains(HttpContent content, string suffixofSha1)
        {
            using (var streamReader = new StreamReader(await content.ReadAsStreamAsync()))
            {
                while (!streamReader.EndOfStream)
                {
                    var line = await streamReader.ReadLineAsync();
                    var segments = line.Split(':');
                    if (segments.Length == 2
                        && string.Equals(segments[0], suffixofSha1, StringComparison.OrdinalIgnoreCase)
                        && long.TryParse(segments[1], out var count))
                    {
                        return count;
                    }
                }
            }
            return 0;
        }
    }
}
