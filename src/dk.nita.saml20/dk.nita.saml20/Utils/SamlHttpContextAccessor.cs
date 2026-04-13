using System.Threading;
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

        // AsyncLocal set in ProcessRequest so Current always returns the exact context being
        // handled, even if IHttpContextAccessor.HttpContext is null or points elsewhere.
        private static readonly AsyncLocal<HttpContext> _explicitContext = new AsyncLocal<HttpContext>();

        public static void Configure(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        /// <summary>
        /// Called by Saml20AbstractEndpointHandler.ProcessRequest before invoking Handle(), and
        /// by host applications when they need to pin a specific HttpContext for SAML session
        /// lookups (e.g. from a DI factory that runs before the SAML handler sets this).
        /// Stores the request context in an AsyncLocal so all static session helpers on this
        /// execution path see the correct HttpContext regardless of IHttpContextAccessor state.
        /// </summary>
        public static void SetExplicitContext(HttpContext context)
        {
            _explicitContext.Value = context;
        }

        public static HttpContext Current => _explicitContext.Value ?? _httpContextAccessor?.HttpContext;
    }
}
