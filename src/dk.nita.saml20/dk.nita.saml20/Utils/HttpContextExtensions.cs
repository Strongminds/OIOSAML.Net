using System.Linq;
using Microsoft.AspNetCore.Http;

namespace dk.nita.saml20.Utils
{
    internal static class HttpContextExtensions
    {
        /// <summary>
        /// Mimics ASP.NET classic Request.Params["key"] by searching Query then Form.
        /// </summary>
        internal static string GetRequestParam(this HttpContext context, string key)
        {
            return context.Request.Query[key].FirstOrDefault()
                ?? (context.Request.HasFormContentType ? context.Request.Form[key].FirstOrDefault() : null);
        }

        /// <summary>
        /// Mimics ASP.NET classic Request.Params["key"] by searching Query then Form.
        /// </summary>
        internal static string GetRequestParam(this HttpRequest request, string key)
        {
            return request.Query[key].FirstOrDefault()
                ?? (request.HasFormContentType ? request.Form[key].FirstOrDefault() : null);
        }
    }
}
