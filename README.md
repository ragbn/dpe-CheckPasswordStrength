# CheckPasswordStrength

This repository contains a library, console application, Test project and API.

# CheckPasswordStrength Library 

* Calculates password entropy bits based on formula E = Log2(R^L). R = Pool of unique characters, L = Length of password, R^L = number of possible passwords, Log2(R^L) = Entropy bits. 

```csharp

            double charpool = Math.Log(CalculateCharPool(password)) / Math.Log(2.0);

```
* Validates if password is pwned by calling https://api.pwnedpasswords.com/range/ passing the first 5 char of SHA1 hash of password.

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

# CheckPasswordStrength.Test



# CheckPasswordStrengthConsole
  