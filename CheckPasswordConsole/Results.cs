using System;
using System.Collections.Generic;
using System.Text;

namespace CheckPasswordConsole
{
    class Results
    {
        public bool IsCommonPassword { get; set; }
        public double EntropyBits { get; set; }
        public long PwnedCount { get; set; }
    }
}
