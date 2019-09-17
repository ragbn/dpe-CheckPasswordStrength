using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using CheckPasswordStrength;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

[assembly: InternalsVisibleTo("DetermineStrengthService.Test")]
namespace CheckPasswordStrength
{
    public class DetermineStrengthService : IDetermineStrengthService
    {
        private readonly IHttpClientFactory _clientFactory;
        readonly ILogger<DetermineStrengthService> _logger;

        /// <summary>
        /// Creates new instance of <see cref="DetermineStrengthService"/>
        /// </summary>
        /// <param name="logger"></param>
        public DetermineStrengthService(ILogger<DetermineStrengthService> logger, IHttpClientFactory clientFactory)
        {
            _logger = logger;
            _clientFactory = clientFactory;
        }

        /// <summary>
        /// Verify if password is common and calculate entropy bit.
        /// </summary>
        /// <param name="password"></param>
        /// <returns> Serialize Json Object as string </returns>
        public async Task<string> CheckStrength(string password)
        {
            // load common words and frequency dictionary. 
            UtilCommonWords.Parse_Common();
            UtilFrequencyList.Parse_Frequency();

            string resultJson;
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password cannot be null or empty.");
            }
            // Check if common password ex: apple, password etc.
            var IsCommon = await Task.FromResult(IsCommonPassword(password.ToLower()));
            // Calculate entropy bits to determine strength
            double EntropyBit = await Task.FromResult(CalculateEntropyBit(password));
            // Check if password appeared in data breach
            long pwnedCount = await CheckIfPwned(password);

            DetermineStrengthResults result = new DetermineStrengthResults
            {
                IsCommonPassword = IsCommon,
                EntropyBits = EntropyBit,
                PwnedCount = pwnedCount
            };

            resultJson = JsonConvert.SerializeObject(result);
            return resultJson;

        }

        /// <summary>
        /// Checks if password is common. Ex: apple, password etc.
        /// </summary>
        /// <param name="lpassword"></param>
        /// <returns>Returns true if password is common else false</returns>
        private bool IsCommonPassword(string lpassword)
        {
            try
            {
                for (int i = 1; i < UtilCommonWords.CommonWords.Count; i++)
                {
                    if (UtilCommonWords.CommonWords[i] == lpassword)
                    {
                        i = UtilCommonWords.CommonWords.Count;

                        return true;

                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking if password is common");
            }
            return false;
        }

        /// <summary>
        /// Calculates entropy bit and rounds off using the formula E= log2(R^L) 
        /// Where E = entropy, R = pool of chars, L = Length of password
        /// Higher the value of E, better the password strength
        /// </summary>
        /// <param name="password"></param>
        /// <returns>Returns entropy bit of type double</returns>
        internal double CalculateEntropyBit(string password)
        {
            double bits = 0;
            double entropy = Math.Log(CalculateCharPool(password)) / Math.Log(2.0);
            int aidx = GetIndex(password.ToLower()[0]);
            int bidx;
            try
            {
                for (int i = 1; i < password.ToLower().Length; i++)
                {
                    bidx = GetIndex(password.ToLower()[i]);
                    double d = 1.0 - UtilFrequencyList.FrequencyTable[aidx * 27 + bidx];
                    bits += entropy * d * d;
                    aidx = bidx;
                }

                return Math.Round(bits * 10) / 10;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error calcuating entropy bit");
                return -1;
            }
        }

        /// <summary>
        /// Calculates index of a character.(a=1,y=26)
        /// </summary>
        /// <param name="i"></param>
        /// <returns> Returns index value as integer</returns>
        internal int GetIndex(char i)
        {
            int returnValue = 0;

            if (i < 'a' || i > 'z')
            {
                return 0;
            }
            try
            {
                const int a = (int)'a' - 1;
                returnValue *= 26;
                returnValue += (int)i - a;
                return returnValue;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting index of character");
                return -1;
            }
        }
        /// <summary>
        /// Calculates character pool for given password. 
        /// Ex: "Password" = [A-Z][a-z] = 26+26 = 52
        /// </summary>
        /// <param name="password"></param>
        /// <returns>Returns char pool value as integer</returns>
        internal int CalculateCharPool(string password)
        {
            int value = 0;
            if (Regex.Matches(password, "[-`~_=+[{}\\|;:'\",<>/?.]").Count > 0)  //]
            {
                value = value + 19;
            }
            if (Regex.Matches(password, "[A-Z]").Count > 0)
            {
                value = value + 26;
            }
            if (Regex.Matches(password, "[a-z]").Count > 0)
            {
                value = value + 26;
            }
            if (Regex.Matches(password, "[0-9]").Count > 0)
            {
                value = value + 10;
            }
            if (Regex.Matches(password, "[]]").Count > 0)
            {
                value = value + 1;
            }
            if (Regex.Matches(password, "[!@#$%^&*()]").Count > 0)
            {
                value = value + 10;
            }
            if (Regex.Matches(password, "[\x20]").Count > 0)
            {
                value = value + 1;
            }
            return value;
        }

        /// <summary>
        /// Compute SHA1 of the password and check if password is pwned by passing first 5 char of hash to api.pwnedpasswords.com
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        internal async Task<long> CheckIfPwned(string password)
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
