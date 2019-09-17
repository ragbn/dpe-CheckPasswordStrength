using System;
using System.Text;
using Microsoft.Extensions.Logging;
using Moq;

namespace DetermineStrengthServiceTests
{
    public static class UtilHelper
    {
        public static ILogger<T> StubLogger<T>()
        {
            var stub = new Mock<ILogger<T>>();
            return stub.Object;
        }

    }
}