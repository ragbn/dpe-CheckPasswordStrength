using System;
using Xunit;
using Microsoft.Extensions.DependencyInjection;
using System.Reflection;
using System.Net.Http;
using DetermineStrengthServiceTests;
using System.Threading.Tasks;
using CheckPasswordConsole;
using Newtonsoft.Json;

namespace CheckPasswordStrength.Test
{
    
    public class DetermineStrengthServiceTests
    {
        [Fact]
        public void DetermineStrength_WhenNullValues_GetArgumentException()
        {
            DetermineStrengthService service = GetClient();

            Assert.ThrowsAsync<ArgumentException>(async () => await service.CheckStrength(null));

        }

        [Fact]
        public void DetermineStrength_WhenEmptyPassword_GetArgumentException()
        {
            DetermineStrengthService service = GetClient();

            Assert.ThrowsAsync<ArgumentException>(async () => await service.CheckStrength(string.Empty));


        }
        [Fact]
        public async Task DetermineStrength_WhenVeryWeakPassword_ReturnEntropyBitRange()
        {
            DetermineStrengthService service = GetClient();

            var veryWeakPassword = "pass@1";

            var result = await service.CheckStrength(veryWeakPassword);
            Results value = JsonConvert.DeserializeObject<Results>(result);

            Assert.True(value.EntropyBits < 28);

        }

        [Fact]
        public async Task DetermineStrength_WhenWeakPassword_ReturnEntropyBitRange()
        {
            DetermineStrengthService service = GetClient();

            var weakPassword = "pa$$word";

            var result = await service.CheckStrength(weakPassword);
            Results value = JsonConvert.DeserializeObject<Results>(result);

            Assert.True(value.EntropyBits < 36);

        }

        [Fact]
        public async Task DetermineStrength_WhenFairlyStrongPassword_ReturnEntropyBitRange()
        {
            DetermineStrengthService service = GetClient();

            var fairlyStrongPassword = "#m4mvF8LLe";

            var result = await service.CheckStrength(fairlyStrongPassword);
            Results value = JsonConvert.DeserializeObject<Results>(result);

            Assert.True(value.EntropyBits < 60);

        }

        [Fact]
        public async Task DetermineStrength_WhenStrongPassword_ReturnEntropyBitRange()
        {
            DetermineStrengthService service = GetClient();

            var strongPassword = "#m4mvF8LLe.s@RV";

            var result = await service.CheckStrength(strongPassword);
            Results value = JsonConvert.DeserializeObject<Results>(result);

            Assert.True(value.EntropyBits < 128);

        }

        [Fact]
        public async Task DetermineStrength_WhenVeryStrongPassword_ReturnEntropyBitRange()
        {
            DetermineStrengthService service = GetClient();

            var verystrongPassword = "jfQ0iF6S5GTNuZuhg/+/0nc9LmrDVGKEBo0nprdR3HXkFneVzen6GcrWBwUf5aMCkzKeM8ck341aLCvrijsmng==";

            var result = await service.CheckStrength(verystrongPassword);
            Results value = JsonConvert.DeserializeObject<Results>(result);

            Assert.True(value.EntropyBits > 128);

        }

        [Fact]
        public async Task DetermineStrength_WhenCommonPassword_ReturnTrue()
        {
            DetermineStrengthService service = GetClient();

            var commonPassword = "abc123";

            var result = await service.CheckStrength(commonPassword);
            Results value = JsonConvert.DeserializeObject<Results>(result);

            Assert.True(value.IsCommonPassword);

        }

        [Fact]
        public async Task DetermineStrength_WhenCommonPassword_ReturnFalse()
        {
            DetermineStrengthService service = GetClient();

            var uncommonPassword = "uBBrHdr1QlnVEuhlKu2pX4V0/P64Pv4FE5vKl+Fe8EGtzr1e5mSc16DGP+vyFWPXrt0cFUzoSqiFZqnJF7mRog==";

            var result = await service.CheckStrength(uncommonPassword);
            Results value = JsonConvert.DeserializeObject<Results>(result);

            Assert.False(value.IsCommonPassword);

        }

        [Fact]
        public async Task DetermineStrength_WhenBreachedPassword_ReturnCount()
        {
            DetermineStrengthService service = GetClient();

            var breachedPassword = "qwerty";

            var result = await service.CheckStrength(breachedPassword);
            Results value = JsonConvert.DeserializeObject<Results>(result);

            Assert.True(value.PwnedCount > 0);

        }

        [Fact]
        public async Task DetermineStrength_WhenBreachedPassword_ReturnZero()
        {
            DetermineStrengthService service = GetClient();

            var weakPassword = "XmZvZ4qDLa1erY9+elJtsSpWkndk58nzSfWJDi18HOKsb4Z4wo2XD+/qPXP2Eo+HmzMM10hlZR2Sf9apMNCYyA==";

            var result = await service.CheckStrength(weakPassword);
            Results value = JsonConvert.DeserializeObject<Results>(result);

            Assert.True(value.PwnedCount == 0);

        }

        public static DetermineStrengthService GetClient()
        {
            var collection = new ServiceCollection();

            collection.AddHttpClient<IDetermineStrengthService, DetermineStrengthService>();

            var serviceProvider = collection.BuildServiceProvider();
            _ = serviceProvider.GetService<DetermineStrengthService>();

            DetermineStrengthService service = new DetermineStrengthService(UtilHelper.StubLogger<DetermineStrengthService>(), serviceProvider.GetRequiredService<IHttpClientFactory>());

            return service;
        }
    }
}
