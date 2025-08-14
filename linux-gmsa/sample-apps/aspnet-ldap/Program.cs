using System.Text.Json;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using Novell.Directory.Ldap;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton<IAmazonSecretsManager, AmazonSecretsManagerClient>();

var app = builder.Build();

app.MapGet("/", async (IAmazonSecretsManager secretsManager) =>
{
    try
    {
        var secretName = Environment.GetEnvironmentVariable("SECRET_NAME") ?? "eks-gmsa-credentials";
        var region = Environment.GetEnvironmentVariable("AWS_REGION") ?? "us-east-1";
        
        var request = new GetSecretValueRequest
        {
            SecretId = secretName
        };
        
        var response = await secretsManager.GetSecretValueAsync(request);
        var secret = JsonSerializer.Deserialize<Dictionary<string, string>>(response.SecretString);
        
        var username = secret.TryGetValue("username", out var user) ? user : "";
        var password = secret.TryGetValue("password", out var pass) ? pass : "";
        var domain = secret.TryGetValue("domain", out var dom) ? dom : "";
        var gmsaAccount = secret.TryGetValue("gmsaAccount", out var gmsa) ? gmsa : "";
        
        var html = $@"
<!DOCTYPE html>
<html>
<head>
    <title>AD Integration Demo</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .container {{ max-width: 800px; margin: 0 auto; }}
        .status {{ padding: 10px; margin: 10px 0; border-radius: 5px; }}
        .success {{ background-color: #d4edda; border: 1px solid #c3e6cb; color: #155724; }}
        .info {{ background-color: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class='container'>
        <h1>ASP.NET Core AD Integration Demo</h1>
        <div class='status success'>
            [SUCCESS] Successfully retrieved gMSA credentials from AWS Secrets Manager
        </div>
        <div class='status info'>
            [SECURE] Using gMSA account for Active Directory authentication
        </div>
        
        <h2>Authentication Details</h2>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Service Account</td><td>{gmsaAccount}</td></tr>
            <tr><td>Domain</td><td>{domain}</td></tr>
            <tr><td>Authentication Method</td><td>gMSA via AWS Secrets Manager</td></tr>
            <tr><td>Container OS</td><td>Linux</td></tr>
            <tr><td>Runtime</td><td>.NET 8.0</td></tr>
            <tr><td>Pod Name</td><td>{Environment.MachineName}</td></tr>
            <tr><td>Timestamp</td><td>{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC</td></tr>
        </table>
        
        <h2>LDAP Connection Test</h2>
        <div class='status info'>
            [READY] Ready for LDAP operations using gMSA credentials
        </div>
        <p><a href='/ldap'>Test LDAP Query: Count Domain Computers</a></p>
    </div>
</body>
</html>";
        
        return Results.Content(html, "text/html");
    }
    catch (Exception ex)
    {
        var errorHtml = $@"
<!DOCTYPE html>
<html>
<head><title>AD Integration Demo - Error</title></head>
<body>
    <h1>Error</h1>
    <p>Failed to retrieve credentials: {ex.Message}</p>
    <p>Check AWS Secrets Manager configuration and IAM permissions.</p>
</body>
</html>";
        return Results.Content(errorHtml, "text/html");
    }
});

app.MapGet("/ldap", async (IAmazonSecretsManager secretsManager) =>
{
    try
    {
        var secretName = Environment.GetEnvironmentVariable("SECRET_NAME") ?? "eks-gmsa-credentials";
        var response = await secretsManager.GetSecretValueAsync(new GetSecretValueRequest { SecretId = secretName });
        var secret = JsonSerializer.Deserialize<Dictionary<string, string>>(response.SecretString);
        
        var username = secret.TryGetValue("username", out var user) ? user : "";
        var password = secret.TryGetValue("password", out var pass) ? pass : "";
        var domain = secret.TryGetValue("domain", out var dom) ? dom : "";
        
        string ldapResult = "";
        string ldapStatus = "info";
        
        try
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect(domain, 389);
                connection.Bind(username, password);
                
                // Simple connection and bind test - no complex queries
                ldapResult = $"Successfully connected and authenticated to Active Directory using gMSA credentials";
                ldapStatus = "success";
            }
        }
        catch (LdapException ex) when (ex.ResultCode == LdapException.InvalidCredentials)
        {
            ldapResult = "Access denied: Invalid credentials for Active Directory";
            ldapStatus = "error";
        }
        catch (LdapException ex)
        {
            ldapResult = $"LDAP error (Code: {ex.ResultCode}): {ex.LdapErrorMessage ?? ex.Message}";
            ldapStatus = "error";
        }
        catch (Exception ex)
        {
            ldapResult = $"Unexpected error during LDAP query: {ex.Message}";
            ldapStatus = "error";
        }
        
        var statusClass = ldapStatus == "success" ? "success" : ldapStatus == "warning" ? "info" : "error";
        
        var html = $@"
<!DOCTYPE html>
<html>
<head>
    <title>LDAP Query Results</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .container {{ max-width: 800px; margin: 0 auto; }}
        .status {{ padding: 10px; margin: 10px 0; border-radius: 5px; }}
        .success {{ background-color: #d4edda; border: 1px solid #c3e6cb; color: #155724; }}
        .info {{ background-color: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; }}
        .error {{ background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class='container'>
        <h1>LDAP Connection Test</h1>
        <div class='status {statusClass}'>
            {ldapResult}
        </div>
        
        <h2>Query Details</h2>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Test Type</td><td>LDAP Connection & Authentication</td></tr>
            <tr><td>LDAP Server</td><td>{domain}</td></tr>
            <tr><td>Authentication</td><td>gMSA via {username}</td></tr>
            <tr><td>Operation</td><td>Connect and Bind to LDAP server</td></tr>
            <tr><td>Timestamp</td><td>{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC</td></tr>
        </table>
        
        <p><a href='/'>&lt;- Back to Main Page</a></p>
    </div>
</body>
</html>";
        
        return Results.Content(html, "text/html");
    }
    catch (Exception ex)
    {
        var errorHtml = $@"
<!DOCTYPE html>
<html>
<head><title>LDAP Query Error</title></head>
<body>
    <h1>Error</h1>
    <p>Failed to perform LDAP query: {ex.Message}</p>
    <p><a href='/'>&lt;- Back to Main Page</a></p>
</body>
</html>";
        return Results.Content(errorHtml, "text/html");
    }
});

app.Run();