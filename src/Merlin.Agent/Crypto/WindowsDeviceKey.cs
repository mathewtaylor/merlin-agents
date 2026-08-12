using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace Merlin.Agent.Crypto;

/// <summary>
/// The Windows key ladder — TPM through the platform crypto provider, falling back to a
/// DPAPI-protected file.
/// </summary>
/// <remarks>
/// Reached only through <see cref="DeviceKey"/>'s <c>OperatingSystem.IsWindows()</c> guard. Split
/// out of the cross-platform entry point so the Windows-only surface is annotated in one place
/// rather than threaded through methods that also run on Unix.
/// </remarks>
[SupportedOSPlatform("windows")]
public static class WindowsDeviceKey
{
    /// <summary>The CNG key container name. Changing it orphans an enrolled device's key.</summary>
    public const string KeyName = "Merlin.Agent.DeviceKey";

    private const string PlatformProvider = "Microsoft Platform Crypto Provider";

    /// <summary>Opens or creates the device key.</summary>
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

    /// <summary>Deletes the TPM-held key, where one exists.</summary>
    public static void DeleteHardwareKey()
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

    /// <summary>Writes a software-held key, replacing any existing one.</summary>
    /// <param name="path">Where the key is stored.</param>
    /// <param name="key">The key to persist.</param>
    public static void WriteSoftwareKey(string path, ECDsa key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(key);

        byte[] pkcs8 = key.ExportPkcs8PrivateKey();

        try
        {
            // DPAPI machine scope: readable by this machine only, and by SYSTEM without a user
            // profile.
            byte[] protectedKey = ProtectedData.Protect(
                pkcs8, optionalEntropy: null, DataProtectionScope.LocalMachine);

            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllBytes(path, protectedKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs8);
        }
    }

    private static ECDsa CreateSoftware(string path)
    {
        ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        WriteSoftwareKey(path, key);

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
