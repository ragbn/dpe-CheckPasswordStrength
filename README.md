# Check Password Strength

This repository contains a aspnet core library, console application, Test project and Web API.

## CheckPasswordStrength Library 

CheckStrength method of the library accepts password as string and returns json object, which consists of password entropy bits, iscommonpassword bool and number of times password appeared in breaches.

```json
{"IsCommonPassword":true,"EntropyBits":28.7,"PwnedCount":3730471}
```

### Calculating Entropy Bits

* Password's entropy is used to to determine how unpredictable a password is. Password's entropy is calculated by finding entropy per character, which is a log base 2 of the   number of characters in the character set used, multiplied by the number by the number of characters in the password itself along with character frequency analysis.    
*  E = Log2(R)*L, 

    R = *Pool of unique characters*<br/>  
    L = *Length of password*<br/>   
    Log2(R)*L = *Entropy bits* 
* Password strength is categorized as 
    
     EntropyBits <= 28 - *very weak*<br/>  
     EntropyBits <= 36 *weak*<br/>  
     EntropyBits <= 60 *fairly strong*<br/>  
     EntropyBits <= 128 *strong*<br/>  
     EntropyBits > 128 *very strong*<br/>

```csharp

            double charpool = Math.Log(CalculateCharPool(password)) / Math.Log(2.0);

```

### Check if password is common

* Very basic compression algorithm is used, if first character is upper case then copy N letters from previous word. 
* A variable of type string is assigned with fixed set of characters for calculation.



### Finding number of time password appeared in data breach.

* SHA1 hash of given password will be calculated and first 5 characters are posted to https://api.pwnedpasswords.com/range/ to get breach count.
* CheckIfPwned uses aspnet core HTTPClient factory to configure and manage instances.

```csharp


            var request = new HttpRequestMessage(HttpMethod.Get, "https://api.pwnedpasswords.com/range/" + prefixofSha1);
            var client = _clientFactory.CreateClient();
            try
            {
                var response = await client.SendAsync(request);

                if (response.IsSuccessStatusCode)
                {
          
                    var PwnedFrequency = await Contains(response.Content, suffixofSha1);
                    var PwnedCount = (PwnedFrequency >= 1);
                    return PwnedFrequency;

                }
            }
```

## CheckPasswordStrength.Test

* Tests if argument exception is thrown, when null is passed.

```csharp

 public void DetermineStrength_WhenNullValues_GetArgumentException()
        {
            DetermineStrengthService service = GetClient();

            Assert.ThrowsAsync<ArgumentException>(async () => await service.CheckStrength(null));

        }
```
* Test if method returns true if very common password is passed

```csharp
 [Fact]
        public async Task DetermineStrength_WhenCommonPassword_ReturnTrue()
        {
            DetermineStrengthService service = GetClient();

            var commonPassword = "password";

            var result = await service.CheckStrength(commonPassword);
            Results value = JsonConvert.DeserializeObject<Results>(result);

            Assert.True(value.IsCommonPassword);

        }
```
* Tests if entropy bit is greater than 128 bit, when very strong password is passed.

```csharp
 public async Task DetermineStrength_WhenVeryStrongPassword_ReturnEntropyBitRange()
        {
            DetermineStrengthService service = GetClient();

            var verystrongPassword = "jfQ0iF6S5GTNuZuhg/+/0nc9LmrDVGKEBo0nprdR3HXkFneVzen6GcrWBwUf5aMCkzKeM8ck341aLCvrijsmng==";

            var result = await service.CheckStrength(verystrongPassword);
            Results value = JsonConvert.DeserializeObject<Results>(result);

            Assert.True(value.EntropyBits > 128);

        }
```

* Tests if 0 is returned, when unbreachable password is passed

```csharp
 [Fact]
        public async Task DetermineStrength_WhenBreachedPassword_ReturnZero()
        {
            DetermineStrengthService service = GetClient();

            var weakPassword = "XmZvZ4qDLa1erY9+elJtsSpWkndk58nzSfWJDi18HOKsb4Z4wo2XD+/qPXP2Eo+HmzMM10hlZR2Sf9apMNCYyA==";

            var result = await service.CheckStrength(weakPassword);
            Results value = JsonConvert.DeserializeObject<Results>(result);

            Assert.True(value.PwnedCount == 0);

        }
```
* Many more such cases are tested.

## CheckPasswordStrengthConsole
  