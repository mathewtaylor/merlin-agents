using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace Merlin.Agent.Crypto;

/// <summary>Where a device's private key is held.</summary>
public enum KeyAttestation
{
    /// <summary>Held in the machine's TPM and non-exportable.</summary>
    Tpm,

    /// <summary>Held in software, protected at rest by DPAPI under the machine key.</summary>
    Software,
}

/// <summary>
/// The device's signing key — created once at enrolment, used for every request afterwards, and
/// never leaving this machine.
/// </summary>
/// <remarks>
/// <para>
/// <b>TPM first, software second, and the report says which.</b> A TPM-held key is created with
/// <see cref="CngExportPolicies.None"/> inside the platform crypto provider, so it cannot be
/// extracted even by an administrator on this machine: a report signed with it provably came from
/// this physical device. A software key can be copied and used from anywhere, which is materially
/// weaker evidence — so the attestation travels with every enrolment and Merlin shows it beside the
/// device rather than quietly treating both the same.
/// </para>
/// <para>
/// <b>The fallback is not optional.</b> The customer this agent is built for runs consumer hardware,
/// and a machine with no usable TPM is common rather than exceptional. Refusing to enrol such a
/// machine would leave it entirely unmonitored, which is strictly worse than monitoring it with a
/// weaker key and saying so.
/// </para>
/// <para>
/// <b>What this does NOT protect against.</b> The key proves provenance, not truth. A local
/// administrator can modify this agent and have it sign whatever they like; a TPM stops the key
/// being stolen and used elsewhere, not the legitimate holder lying. See <c>docs/security.md</c>.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public static class DeviceKey
{
    /// <summary>The CNG key container name. Changing it orphans an enrolled device's key.</summary>
    public const string KeyName = "Merlin.Agent.DeviceKey";

    private const string PlatformProvider = "Microsoft Platform Crypto Provider";

    /// <summary>
    /// Opens the existing device key, or creates one if this machine has never enrolled.
    /// </summary>
    /// <param name="softwareKeyPath">Where a software-held key is stored.</param>
    /// <returns>The signer and how the key is held.</returns>
    public static (ECDsa Key, KeyAttestation Attestation) OpenOrCreate(string softwareKeyPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(softwareKeyPath);

        if (TryOpenTpm(out ECDsa? existing))
        {
            return (existing!, KeyAttestation.Tpm);
        }

        if (File.Exists(softwareKeyPath))
        {
            return (LoadSoftware(softwareKeyPath), KeyAttestation.Software);
        }

        if (TryCreateTpm(out ECDsa? created))
        {
            return (created!, KeyAttestation.Tpm);
        }

        return (CreateSoftware(softwareKeyPath), KeyAttestation.Software);
    }

    /// <summary>Deletes the device key, so the machine can enrol afresh.</summary>
    /// <param name="softwareKeyPath">Where a software-held key is stored.</param>
    public static void Delete(string softwareKeyPath)
    {
        try
        {
            if (CngKey.Exists(KeyName, new CngProvider(PlatformProvider), CngKeyOpenOptions.MachineKey))
            {
                using CngKey key = CngKey.Open(
                    KeyName, new CngProvider(PlatformProvider), CngKeyOpenOptions.MachineKey);
                key.Delete();
            }
        }
        catch (CryptographicException)
        {
            // A key that cannot be opened cannot be deleted either, and there is nothing useful to
            // do about it here: uninstall continues, and re-enrolling produces a new device row for
            // an administrator to reconcile.
        }

        if (File.Exists(softwareKeyPath))
        {
            File.Delete(softwareKeyPath);
        }
    }

    /// <summary>The Base64 SPKI DER public key, which is the device's real identity.</summary>
    /// <param name="key">The signer.</param>
    /// <returns>Base64 SPKI DER.</returns>
    public static string PublicKey(ECDsa key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());
    }

    /// <summary>Signs a canonical string.</summary>
    /// <param name="key">The signer.</param>
    /// <param name="canonical">The canonical string.</param>
    /// <returns>Base64 IEEE P1363 signature.</returns>
    public static string Sign(ECDsa key, string canonical)
    {
        ArgumentNullException.ThrowIfNull(key);

        byte[] signature = key.SignData(
            Core.Crypto.AgentSignature.BytesToSign(canonical), HashAlgorithmName.SHA256);

        return Convert.ToBase64String(signature);
    }

    private static bool TryOpenTpm(out ECDsa? key)
    {
        key = null;

        try
        {
            if (!CngKey.Exists(KeyName, new CngProvider(PlatformProvider), CngKeyOpenOptions.MachineKey))
            {
                return false;
            }

            CngKey handle = CngKey.Open(
                KeyName, new CngProvider(PlatformProvider), CngKeyOpenOptions.MachineKey);

            key = new ECDsaCng(handle);
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch (PlatformNotSupportedException)
        {
            return false;
        }
    }

    private static bool TryCreateTpm(out ECDsa? key)
    {
        key = null;

        try
        {
            CngKeyCreationParameters parameters = new()
            {
                Provider = new CngProvider(PlatformProvider),

                // Non-exportable is the entire point: it is what makes a signature evidence about
                // THIS machine rather than about whoever holds a copied key.
                ExportPolicy = CngExportPolicies.None,

                // Machine scope, because the agent runs as SYSTEM from a scheduled task and no user
                // profile is loaded.
                KeyCreationOptions = CngKeyCreationOptions.MachineKey,
            };

            CngKey handle = CngKey.Create(CngAlgorithm.ECDsaP256, KeyName, parameters);
            key = new ECDsaCng(handle);
            return true;
        }
        catch (CryptographicException)
        {
            // No TPM, a TPM that is not ready, or a provider that refuses the request. All of them
            // mean the same thing here: fall back and report the weaker attestation honestly.
            return false;
        }
        catch (PlatformNotSupportedException)
        {
            return false;
        }
    }

    private static ECDsa CreateSoftware(string path)
    {
        ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] pkcs8 = key.ExportPkcs8PrivateKey();

        // DPAPI machine scope: readable by this machine only, and by SYSTEM without a user profile.
        byte[] protectedKey = ProtectedData.Protect(pkcs8, optionalEntropy: null, DataProtectionScope.LocalMachine);
        CryptographicOperations.ZeroMemory(pkcs8);

        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, protectedKey);

        return key;
    }

    private static ECDsa LoadSoftware(string path)
    {
        byte[] pkcs8 = ProtectedData.Unprotect(
            File.ReadAllBytes(path), optionalEntropy: null, DataProtectionScope.LocalMachine);

        ECDsa key = ECDsa.Create();
        key.ImportPkcs8PrivateKey(pkcs8, out _);
        CryptographicOperations.ZeroMemory(pkcs8);

        return key;
    }
}
