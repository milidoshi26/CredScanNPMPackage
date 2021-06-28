# CredScanConsoleApp

This is a simple console app based on [CredScan-SDK](https://msazure.visualstudio.com/One/_git/SecEng-CredScan-SDK?version=GBdev) to scan for credentials in logs.

## Steps

1. Update the ```FILE_PATH``` to log file. By default, ```FILE_PATH``` is set to ```logs.txt```.
2. Build the project using ```dotnet build```.
3. Copy the ```configFiles``` folder in ```bin/Debug/net5.0```.
4. Run the project. App will console out the lines and info about credentials found in the logs. 
5. Delete the logs file, created in step 1.

Package source for Microsoft.Security.CredScan.KnowledgeBase.Client can be found [Here]( https://pkgs.dev.azure.com/msazure/One/_packaging/CredScanDev/nuget/v3/index.json). Add this to your project if the package is not found.

Note - In order to test if app is working fine, add the below line in your logs.

    "Mongo Connection string mongodb://mongodb-example:erSNrY3Ucc3Q1v3JzDbfvRDiwj7n082WikBhX6C0VZa8lddDrqQN2yYiHpNoXhFLcsrOtmsK5bcVPriIWIt8KQ==@example-example.documents.azure.com:10255/store?ssl=true&sslverifycertificate=false&replicaSet=globaldb&connectTimeoutMS=300000&socketTimeoutMS=300000&retryWrites=true"
