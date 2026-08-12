using System.Runtime.Versioning;
using System.Security.Cryptography;
using Merlin.Agent.State;

namespace Merlin.Agent.Crypto;

/// <summary>
/// The macOS and Linux key store — a PKCS#8 private key in a root-only file.
/// </summary>
/// <remarks>
/// <para>
/// <b>File permissions, not encryption, and the documentation says so plainly.</b> DPAPI has no
/// equivalent on either platform that is worth the name: macOS's Keychain and Linux's kernel keyring
/// both hold the key under the same root identity the agent already runs as, so encrypting with them
/// would protect the key from an attacker who — by construction — is already root and can read the
/// process's memory. Writing <c>0600</c> and saying "this is protected by file permissions" is the
/// accurate description; wrapping it in a key only root can fetch and calling it "encrypted at rest"
/// would be theatre.
/// </para>
/// <para>
/// <b>The permissions are set BEFORE the key bytes are written, not after.</b> Creating the file
/// with a default mode and then tightening it leaves a window — however brief — in which the private
/// key is world-readable, and on a multi-user machine that window is the whole attack.
/// </para>
/// <para>
/// The attestation reported for a key held this way is always
/// <see cref="KeyAttestation.Software"/>. See <see cref="DeviceKey"/> for why a Secure Enclave or
/// TPM key is not claimed on the strength of the hardware being present.
/// </para>
/// </remarks>
[UnsupportedOSPlatform("windows")]
public static class UnixDeviceKey
{
    private const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    /// <summary>Opens the existing key, or creates one.</summary>
    /// <param name="path">Where the key is stored.</param>
    /// <returns>The signer.</returns>
    public static ECDsa OpenOrCreate(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        return File.Exists(path) ? Load(path) : Create(path);
    }

    /// <summary>Writes a key, replacing any existing one.</summary>
    /// <param name="path">Where the key is stored.</param>
    /// <param name="key">The key to persist.</param>
    public static void Write(string path, ECDsa key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(key);

        AgentState.EnsureDirectory();

        byte[] pkcs8 = key.ExportPkcs8PrivateKey();

        try
        {
            // Opened with the restrictive mode applied at creation, so the key bytes are never
            // readable by anyone but root even momentarily.
            using FileStream stream = new(
                path,
                new FileStreamOptions
                {
                    Mode = FileMode.Create,
                    Access = FileAccess.Write,
                    Share = FileShare.None,
                    UnixCreateMode = OwnerOnly,
                });

            stream.Write(pkcs8);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs8);
        }
    }

    private static ECDsa Create(string path)
    {
        ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Write(path, key);

        return key;
    }

    private static ECDsa Load(string path)
    {
        byte[] pkcs8 = File.ReadAllBytes(path);

        try
        {
            ECDsa key = ECDsa.Create();
            key.ImportPkcs8PrivateKey(pkcs8, out _);
            return key;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs8);
        }
    }
}
