using System.Security.Cryptography;
using System.Text;

namespace CheckPasswordStrength
{
    /// <summary>
    /// Util to generate SHA1 has of the password 
    /// </summary>
 
    internal static class UtilCryptoSHA1
    {
        private static readonly SHA1 _sha1 = SHA1.Create();

        /// <summary>
        /// Calculate hash for password
        /// </summary>
        /// <param name="password">String to be hashed</param>
        /// <returns>40  hexadecimal character</returns>
        public static string SHA1HashForPassword(string password)
        {
            byte[] passwordBytes = Encoding.Default.GetBytes(password);

            byte[] passwordhashBytes = _sha1.ComputeHash(passwordBytes);

            return HexFromPasswordBytes(passwordhashBytes);
        }

        /// <summary>
        /// Convert password hash bytes to a string of hexadecimal digits
        /// </summary>
        /// <param name="passwordhashBytes">password has bytes</param>
        /// <returns>String of hexadecimal</returns>
        private static string HexFromPasswordBytes(byte[] passwordhashBytes)
        {
            var sb = new StringBuilder();
            foreach (byte b in passwordhashBytes)
            {
                var hex = b.ToString("X2");
                sb.Append(hex);
            }
            return sb.ToString();
        }
    }
}
