using System;
using System.Threading.Tasks;

namespace CheckPasswordStrength
{
    /// <summary>
    /// Determine the strength of the password by using entropy algorithm 
    /// </summary>
    public interface IDetermineStrengthService
    {
        /// <summary>
        /// Verify if given password is common and calculate entropy bit 
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        Task<string> CheckStrength(string password);
    }
}
