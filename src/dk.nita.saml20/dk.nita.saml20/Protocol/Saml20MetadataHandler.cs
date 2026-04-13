using System;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Http;
using dk.nita.saml20.config;
using Saml2.Properties;
using System.Security.Cryptography.Xml;
using System.Collections.Generic;

namespace dk.nita.saml20.protocol
{
    /// <summary>
    /// The handler that exposes a metadata endpoint to the other parties of the federation.
    ///     
    /// The handler accepts the following GET parameters :
    /// - encoding : Delivers the Metadata document in the specified encoding. Example: encoding=iso-8859-1 . If the parameter is omitted, the encoding utf-8 is used.
    /// - sign : A boolean parameter specifying whether to sign the metadata document. Example: sign=false. If the parameter is omitted, the document is signed.
    /// </summary>
    public class Saml20MetadataHandler : AbstractEndpointHandler
    {
        /// <summary>
        /// Handles the HTTP request.
        /// </summary>
        public override void ProcessRequest(HttpContext context)
        {
            var responseEncoding = Encoding.UTF8;
            var encoding = context.Request.Query["encoding"].ToString();
            try
            {
                if (!string.IsNullOrEmpty(encoding))
                    responseEncoding = Encoding.GetEncoding(encoding);
            }
            catch (ArgumentException)
            {
                HandleError(context, Resources.UnknownEncoding, encoding);
                return;
            }

            var sign = false;
            try
            {
                string param = context.Request.Query["sign"].ToString();
                if (!string.IsNullOrEmpty(param))
                    sign = Convert.ToBoolean(param);
            }
            catch (FormatException)
            {
                HandleError(context, Resources.GenericError);
                return;
            }

            context.Response.ContentType = Saml20Constants.METADATA_MIMETYPE;
            context.Response.Headers["Content-Disposition"] = "attachment; filename=\"metadata.xml\"";

            CreateMetadataDocument(context, sign, responseEncoding);
        }

        private void CreateMetadataDocument(HttpContext context, bool sign, Encoding responseEncoding)
        {
            SAML20FederationConfig configuration = SAML20FederationConfig.GetConfig();

            var keyinfos = new List<KeyInfo>();
            foreach (Certificate certificate in FederationConfig.GetConfig().SigningCertificates)
            {
                KeyInfo keyinfo = new KeyInfo();
                KeyInfoX509Data keyClause = new KeyInfoX509Data(certificate.GetCertificate(), X509IncludeOption.EndCertOnly);
                keyinfo.AddClause(keyClause);
                keyinfos.Add(keyinfo);
            }

            Saml20MetadataDocument doc = new Saml20MetadataDocument(configuration, keyinfos, sign);

            context.Response.WriteAsync(doc.ToXml(responseEncoding)).GetAwaiter().GetResult();
        }
    }
}
