using LDAP_Auth.Models;
using Microsoft.Extensions.Options;
using System.DirectoryServices;
using System.Reflection.PortableExecutable;

namespace LDAP_Auth.Services;

public Task<LdapAuthResult> AuthenticateAsync(string username, string password)
{
    var result = new LdapAuthResult { Username = username };

    try
    {
        string domainUser = $"{_settings.Domain}\\{username}";
        using var entry = new DirectoryEntry(_settings.LdapPath, domainUser, password);
        using var searcher = new DirectorySearcher(entry)
        {
            Filter = $"(sAMAccountName={username})"
        };

        searcher.PropertiesToLoad.Add("memberOf");
        var searchResult = searcher.FindOne();

        if (searchResult != null)
        {
            result.IsAuthenticated = true;

            if (searchResult.Properties["memberOf"] is { Count: > 0 } memberOfCollection)
            {
                foreach (string groupDn in memberOfCollection)
                {
                    // Optional: parse CN=GroupName,... to just GroupName
                    var cn = groupDn.Split(',')[0].Replace("CN=", "");
                    result.Groups.Add(cn);
                }
            }
        }
    }
    catch
    {
        // Optional: log exception
    }

    return Task.FromResult(result);
}

