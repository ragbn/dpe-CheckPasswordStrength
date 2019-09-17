using System;
using System.Threading.Tasks;
using CheckPasswordStrength;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;

namespace CheckPasswordConsole
{
    class Program
    {
        static async Task Main(string[] args)
        {
            var collection = new ServiceCollection();
            collection.AddLogging();
            collection.AddHttpClient<DetermineStrengthService>();
            collection.AddTransient<IDetermineStrengthService, DetermineStrengthService>();
            var serviceProvider = collection.BuildServiceProvider();
            var service = serviceProvider.GetService<IDetermineStrengthService>();
           
            string val;
            do
            {
                Console.WriteLine("Please enter the password ");
                string password = Console.ReadLine();

                string res = await service.CheckStrength(password);

                if(res != null)
                {
                Results results = JsonConvert.DeserializeObject<Results>(res);

                if (password.Length <= 4)
                {
                    Console.ForegroundColor = ConsoleColor.DarkRed;
                    Console.WriteLine("Very short password");
                    Console.ResetColor();
                }
                else if (password.Length < 8)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Short password");
                    Console.ResetColor();
                }

                if (results.IsCommonPassword)
                {
                    Console.ForegroundColor = ConsoleColor.DarkRed;
                    Console.WriteLine("Common password");
                    Console.ResetColor();
                }

                if(results.PwnedCount != 0)
                {
                    Console.ForegroundColor = ConsoleColor.DarkRed;
                    Console.WriteLine("Your password appeared "+ results.PwnedCount + " times in data breaches.");
                    Console.ResetColor();
                }

                if (results.PwnedCount == 0)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("Great choice! Your password did not appear in data breaches.");
                    Console.ResetColor();
                }

                if (results.EntropyBits <= 28)
                {
                    Console.ForegroundColor = ConsoleColor.DarkRed;
                    Console.WriteLine("This password is very weak.");
                    Console.ResetColor();

                }
                else if (results.EntropyBits <= 36)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("This password is weak.");
                    Console.ResetColor();

                }
                else if (results.EntropyBits <= 60)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("This password is fairly strong.");
                    Console.ResetColor();
                }
                else if (results.EntropyBits <= 128)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("This password is strong");
                    Console.ResetColor();
         
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.DarkGreen;
                    Console.WriteLine("Great choice! Very strong password.");
                    Console.ResetColor();
                }

                    Console.ForegroundColor = ConsoleColor.Blue;
                    Console.WriteLine("Entropy Bit: "+results.EntropyBits);
                    Console.ResetColor();
                }
                else if(res == "Error")
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Something went wrong contact your Support.");
                    Console.ResetColor();
                }
                else if(res == null)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Password cannot be empty.");
                    Console.ResetColor();
                }
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                Console.WriteLine("Press c to continue or q to exit....");
                Console.ResetColor();
                val = Console.ReadLine();
            }
            while (val != "q");
        }
    }
}
