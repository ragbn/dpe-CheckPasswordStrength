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
            //configure service used by app
            var collection = new ServiceCollection();
            collection.AddLogging();
            collection.AddHttpClient<DetermineStrengthService>();
            collection.AddTransient<IDetermineStrengthService, DetermineStrengthService>();
            var serviceProvider = collection.BuildServiceProvider();
            var service = serviceProvider.GetService<IDetermineStrengthService>();
           
            do
            {
                
                Console.WriteLine("Please enter the password ");
                string password = Console.ReadLine();
                if (!string.IsNullOrEmpty(password))
                {

                    string res = await service.CheckStrength(password);

                    if (res != null)
                    {
                        Results results = JsonConvert.DeserializeObject<Results>(res);

                        if (password.Length <= 4)
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine("This is a very short password");
                            Console.ResetColor();
                        }
                        else if (password.Length < 8)
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine("This is a short password");
                            Console.ResetColor();
                        }

                        if (results.IsCommonPassword)
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine("This is a common password");
                            Console.ResetColor();
                        }

                        if (results.PwnedCount != 0)
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine("This password appeared " + results.PwnedCount + " times in data breaches.");
                            Console.ResetColor();
                        }

                        if (results.PwnedCount == 0)
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine("This password did not appear in data breaches.");
                            Console.ResetColor();
                        }

                        if (results.EntropyBits <= 28)
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
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
                        Console.WriteLine("Entropy Bit: " + results.EntropyBits);
                        Console.ResetColor();
                    }
                }
                Console.WriteLine("Password cannot be empty");
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                Console.WriteLine("Press any key to continue or esc to exit....");
                Console.ResetColor();
     
            }
            while (Console.ReadKey(true).Key != ConsoleKey.Escape);
        }
    }
}
