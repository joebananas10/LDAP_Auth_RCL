using LDAP_Auth.Models;
using Microsoft.Extensions.Options;
using System.DirectoryServices;
using System.Reflection.PortableExecutable;

namespace LDAP_Auth.Services;

public class LdapAuthService : ILdapAuthService
{
    private readonly LdapSettings _settings;

    public LdapAuthService(IOptions<LdapSettings> settings)
    {
        _settings = settings.Value;
    }

    public Task<bool> AuthenticateAsync(string username, string password)
    {
        try
        {
            // Compose domain-qualified username
            var domainUser = $"{_settings.Domain}\\{username}";

            using (var entry = new System.DirectoryServices.DirectoryEntry(_settings.LdapPath))
            {
                entry.Username = domainUser;
                entry.Password = password;

                // Force bind to check credentials
                var nativeObject = entry.NativeObject; // throws if invalid credentials

                using (var searcher = new DirectorySearcher(entry))
                {
                    searcher.Filter = $"(sAMAccountName={username})";
                    searcher.PropertiesToLoad.Add("cn"); // or any property you want

                    var result = searcher.FindOne();
                    return Task.FromResult(result != null);
                }
            }
        }
        catch
        {
            return Task.FromResult(false);
        }
    }

}