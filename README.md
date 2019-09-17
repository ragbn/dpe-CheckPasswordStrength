# Check Password Strength

This repository contains a aspnet core library, console application, Test project and Web API.

## CheckPasswordStrength Library 

CheckStrength method of the library accepts password as string and returns json object result which consists of Password Entropy bits, is common password and number of times password appeared in breaches.

```json
{"IsCommonPassword":true,"EntropyBits":28.7,"PwnedCount":3730471}
```

### Calculating Entropy Bits

* Password's entropy is used to to determine how unpredictable a password is. Password's entropy is calculated by finding entropy per character, which is a log base 2 of the   number of characters in the character set used, multiplied by the number by the number of characters in the password itself along with character frequency analysis.
    
*  E = Log2(R)*L, 

    -R = Pool of unique characters
    -L = Length of password 
    -Log2(R)*L = Entropy bits. 

```csharp

            double charpool = Math.Log(CalculateCharPool(password)) / Math.Log(2.0);

```

### Check if password is common

* Very basic compression algorithm is used, if first character is upper case then copy N letters from previous word. 
* A variable of type string holds fixed set of characters for calculation.



### Finding number of time password appeared in data breach.
* SHA1 hash of given password will be calculated and first 5 characters of the hash are posted to https://api.pwnedpasswords.com/range/ to get breach count. 

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

### Getting started

# CheckPasswordStrengthConsole
  