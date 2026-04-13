using Microsoft.AspNetCore.Http;
using Saml2.Properties;

namespace dk.nita.saml20.protocol.pages
{
    /// <summary>
    /// A page for displaying error messages
    /// </summary>
    public class ErrorPage : BasePage
    {
        public string ErrorText { get; set; } = string.Empty;
        public bool OverrideConfig { get; set; } = false;

        public override void ProcessRequest(HttpContext context)
        {
            TitleText = Resources.Error;
            HeaderText = Resources.Error;
            BodyContent = ErrorText;
            context.Response.ContentType = "text/html";
            context.Response.WriteAsync(RenderHtml()).GetAwaiter().GetResult();
        }
    }
}
