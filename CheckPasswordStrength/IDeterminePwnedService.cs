using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace CheckPasswordStrength
{
    public interface IDeterminePwnedService
    {
      Task<long> CheckIfPwned(string password);
    }
}
