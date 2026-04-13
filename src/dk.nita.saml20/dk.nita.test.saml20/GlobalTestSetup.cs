using System;
using System.IO;
using System.Reflection;
using System.Xml;
using System.Xml.Serialization;
using dk.nita.saml20.config;
using NUnit.Framework;

/// <summary>
/// Assembly-level setup fixture that ensures SAML configuration is loaded before any test runs.
/// This is needed because System.Configuration.ConfigurationManager does not reliably load
/// custom configuration sections in .NET 10 SDK-style test projects.
/// </summary>
[SetUpFixture]
public class GlobalTestSetup
{
    [OneTimeSetUp]
    public void SetUpConfig()
    {
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        string configPath = Path.Combine(baseDir, "dk.nita.test.saml20.dll.config");

        if (!File.Exists(configPath))
            configPath = Path.Combine(baseDir, "app.config");

        if (!File.Exists(configPath))
            return;

        var doc = new XmlDocument();
        doc.Load(configPath);

        var federationConfig = DeserializeSection<FederationConfig>(doc, "Federation");
        if (federationConfig != null)
            InjectConfig<FederationConfig>(federationConfig);

        var saml20Config = DeserializeSection<SAML20FederationConfig>(doc, "SAML20Federation");
        if (saml20Config != null)
            InjectConfig<SAML20FederationConfig>(saml20Config);
    }

    [OneTimeTearDown]
    public void TearDownConfig()
    {
        FederationConfig.Refresh();
        SAML20FederationConfig.Refresh();
    }

    private static T DeserializeSection<T>(XmlDocument doc, string elementName) where T : class
    {
        XmlNodeList nodes = doc.GetElementsByTagName(elementName);
        if (nodes.Count == 0)
            return null;

        try
        {
            var serializer = new XmlSerializer(typeof(T));
            using var reader = new XmlNodeReader(nodes[0]);
            return (T)serializer.Deserialize(reader);
        }
        catch
        {
            return null;
        }
    }

    private static void InjectConfig<T>(T config) where T : ConfigurationInstance<T>
    {
        Type genericBase = typeof(ConfigurationInstance<T>);
        FieldInfo field = genericBase.GetField("_config", BindingFlags.Static | BindingFlags.NonPublic);
        field?.SetValue(null, config);
    }
}
