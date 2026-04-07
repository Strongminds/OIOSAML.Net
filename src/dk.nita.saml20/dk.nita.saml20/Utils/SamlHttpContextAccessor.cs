using Microsoft.AspNetCore.Http;

namespace dk.nita.saml20.Utils
{
    /// <summary>
    /// Provides static access to IHttpContextAccessor for use in classes that can't use DI.
    /// Must be initialized at application startup by calling Configure(IHttpContextAccessor).
    /// </summary>
    public static class SamlHttpContextAccessor
    {
        private static IHttpContextAccessor _httpContextAccessor;

        public static void Configure(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        public static HttpContext Current => _httpContextAccessor?.HttpContext;
    }
}
