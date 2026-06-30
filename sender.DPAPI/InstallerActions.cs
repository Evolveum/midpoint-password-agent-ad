using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using WixToolset.Dtf.WindowsInstaller;

namespace sender.DPAPI
{
    public static class CustomActions
    {
        [CustomAction]
        public static ActionResult StorePassword(Session session)
        {
            try
            {
                string password = session.CustomActionData["PASSWORD"];
                string configPath = session.CustomActionData["CONFIG"];

                if (string.IsNullOrEmpty(password))
                {
                    session.Log("ProtectPassword: no password supplied, skipping encryption");
                    return ActionResult.Success;
                }

                byte[] plaintext = Encoding.UTF8.GetBytes(password);
                byte[] encrypted = ProtectedData.Protect(
                    plaintext,
                    optionalEntropy: null,
                    scope: DataProtectionScope.LocalMachine);
                string base64 = Convert.ToBase64String(encrypted);
                Array.Clear(plaintext, 0, plaintext.Length);

                JsonObject root;
                if (File.Exists(configPath))
                {
                    string existing = File.ReadAllText(configPath);
                    root = string.IsNullOrWhiteSpace(existing)
                        ? new JsonObject()
                        : (JsonNode.Parse(existing) as JsonObject ?? new JsonObject());
                }
                else
                {
                    root = new JsonObject();
                    Directory.CreateDirectory(Path.GetDirectoryName(configPath));
                }

                if (root["MidPoint"] is JsonObject existingSection)
                {
                    existingSection["Password"] = base64;
                }
                else
                {
                    var secureApiSection = new JsonObject();
                    secureApiSection["Password"] = base64;
                    root["MidPoint"] = secureApiSection;
                }

                var opts = new JsonSerializerOptions { WriteIndented = true };
                File.WriteAllText(configPath, root.ToJsonString(opts));

                session.Log("ProtectPassword: wrote encrypted blob to " + configPath);
                return ActionResult.Success;
            }
            catch (Exception ex)
            {
                session.Log("ProtectPassword failed: " + ex);
                return ActionResult.Failure;
            }
        }
    }
}
