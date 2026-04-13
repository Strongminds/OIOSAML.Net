using System;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using dk.nita.saml20.Properties;
using Trace=dk.nita.saml20.Utils.Trace;

namespace dk.nita.saml20.Specification
{
    /// <summary>
    /// Validates a self-signed certificate
    /// </summary>
    public class SelfIssuedCertificateSpecification : ICertificateSpecification
    {
        /// <summary>
        /// Determines whether the specified certificate is considered valid by this specification.
        /// </summary>
        public bool IsSatisfiedBy(X509Certificate2 certificate, out string failureReason)
        {
            var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

            try
            {
                bool isValid = chain.Build(certificate);
                if (isValid)
                {
                    failureReason = null;
                    return true;
                }
                failureReason = $"Chain validation failed for certificate ''{certificate.Thumbprint}''";
                return false;
            }
            catch (Exception e)
            {
                failureReason = $"Validating with no revocation check failed for certificate ''{certificate.Thumbprint}'': {e}";
                Trace.TraceData(TraceEventType.Warning, string.Format(Tracing.CertificateIsNotRFC3280Valid, certificate.SubjectName.Name, certificate.Thumbprint, e));
                return false;
            }
        }
    }
}
