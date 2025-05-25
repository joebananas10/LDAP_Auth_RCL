using LDAP_Auth.Models;
using LDAP_Auth.Services;
using LDAP_Auth.Utilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace LDAP_Auth.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddLdapAuthentication(this IServiceCollection services, IConfiguration config)
    {
        // Try to bind from configuration
        var section = config.GetSection("LdapSettings");
        var configSettings = section.Get<LdapSettings>();

        // Use auto-detect fallback if config is missing or empty
        var settings = string.IsNullOrWhiteSpace(configSettings?.LdapPath)
            ? LdapEnvironmentDetector.AutoDetect()
            : configSettings;

        // Register settings and service
        services.Configure<LdapSettings>(_ =>
        {
            _.Domain = settings.Domain;
            _.BaseDn = settings.BaseDn;
            _.LdapPath = settings.LdapPath;
        });

        services.AddScoped<ILdapAuthService, LdapAuthService>();

        return services;
    }
}
