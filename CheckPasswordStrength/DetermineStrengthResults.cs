using System;
using System.Collections.Generic;
using System.Text;

namespace CheckPasswordStrength
{
    /// <summary>
    /// Results object which will serialized to Json
    /// </summary>
    public  class DetermineStrengthResults
    {
        public  bool IsCommonPassword { get; set; }
        public  double EntropyBits { get; set; }
        public long PwnedCount { get; set; }
    }
}
