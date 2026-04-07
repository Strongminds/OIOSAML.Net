using Microsoft.AspNetCore.Http;

namespace dk.nita.saml20.protocol.pages
{
    /// <summary>
    /// A base class for SAML protocol pages that write HTML responses.
    /// </summary>
    public abstract class BasePage
    {
        public const string AppSettingsKey = "SafewhereResource";
        public const string DefaultResourcePath = "/SafewhereResource.ashx";

        protected string TitleText { get; set; }
        protected string HeaderText { get; set; }
        protected string FooterText { get; set; }
        protected string BodyContent { get; set; }

        public abstract void ProcessRequest(HttpContext context);

        protected string RenderHtml()
        {
            return $@"<?xml version=""1.0"" encoding=""utf-8""?>
<!DOCTYPE html PUBLIC ""-//W3C//DTD XHTML 1.1//EN"" ""http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd"">
<html xmlns=""http://www.w3.org/1999/xhtml"" xml:lang=""en"">
<head><title>{System.Net.WebUtility.HtmlEncode(TitleText)}</title>
<meta http-equiv=""Content-Type"" content=""text/html; charset=utf-8"" />
</head>
<body>
<div id=""headerPanel"">{HeaderText}</div>
<div id=""bodyPanel"">{BodyContent}</div>
<div id=""footerPanel"">{FooterText}</div>
</body>
</html>";
        }
    }
}
