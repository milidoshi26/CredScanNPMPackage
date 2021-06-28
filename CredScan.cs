    #r "Microsoft.Security.CredScan.KnowledgeBase.Client.dll"
    #r "Microsoft.Security.CredScan.KnowledgeBase.dll"
    #r "Microsoft.Security.RegularExpressions.dll"
    #r "Microsoft.Security.Telemetry.Interfaces.dll"
    #r "netstandard.dll"
    #r "Newtonsoft.Json.dll"

using Microsoft.Security.CredScan.KnowledgeBase.Client;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

// namespace CredScanConsoleApp{
    class Startup
    {
        public async Task<object> Invoke(string msg)
        {
            Console.WriteLine("Scan Started here");
            IEnumerable<CredScanResult> results = null;
            var scanner = new ClientCredentialScanner("FullTextProvider");
            Action<string> scanAction = delegate (string contentToScan)
            {
                results = scanner.Scan(contentToScan);
            };

            scanAction(msg);
            //scanAction("Mongo Connection string mongodb://mongodb-example:erSNrY3Ucc3Q1v3JzDbfvRDiwj7n082WikBhX6C0VZa8lddDrqQN2yYiHpNoXhFLcsrOtmsK5bcVPriIWIt8KQ==@example-example.documents.azure.com:10255/store?ssl=true&sslverifycertificate=false&replicaSet=globaldb&connectTimeoutMS=300000&socketTimeoutMS=300000&retryWrites=true");
            foreach (var credScanResult in results)
            {
                string match = credScanResult.Match.MatchValue;
                //Console.WriteLine(match);
                msg = msg.Replace(match, "REDACTED_CREDENTIALS");
                //Console.WriteLine(msg);
            }

            Console.WriteLine("Scan Completed.");
            return msg;

        }

        public static void Main(string[] args){

        }
    }
// }

