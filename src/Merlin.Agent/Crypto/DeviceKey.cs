using System.Security.Cryptography;
using Merlin.Agent.Platform;

namespace Merlin.Agent.Crypto;

/// <summary>Where a device's private key is held.</summary>
public enum KeyAttestation
{
    /// <summary>Held in the machine's TPM and non-exportable.</summary>
    Tpm,

    /// <summary>
    /// Held in software — protected at rest by DPAPI on Windows, and by file permissions on macOS
    /// and Linux.
    /// </summary>
    Software,
}

/// <summary>
/// The device's signing key — created once at enrolment, used for every request afterwards, and
/// never leaving this machine.
/// </summary>
/// <remarks>
/// <para>
/// <b>Hardware first where the platform offers it, software second, and the report says which.</b> A
/// TPM-held key cannot be extracted even by an administrator on that machine, so a report signed
/// with it provably came from that physical device. A software key can be copied and used from
/// anywhere, which is materially weaker evidence — so the attestation travels with every enrolment
/// and Merlin shows it beside the device rather than quietly treating both the same.
/// </para>
/// <para>
/// <b>Only Windows currently reaches the hardware path, and that is an honest limitation rather
/// than a claim about the hardware.</b> Apple silicon has a Secure Enclave and most Linux machines
/// have a TPM 2.0, and both can hold a non-exportable P-256 key — but reaching them means
/// P/Invoking Security.framework and speaking to <c>/dev/tpmrm0</c> respectively, neither of which
/// .NET exposes. Until then those platforms report <see cref="KeyAttestation.Software"/>, which is
/// the truth about where the key is held. <b>Do not report <c>Tpm</c> on the strength of the
/// hardware existing</b>: the attestation is a statement about the key, and a Mac reporting Tpm
/// while holding its key in a file would be exactly the unearned assurance this whole module
/// refuses. Merlin surfaces the difference; see <c>docs/security.md</c>.
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
/// being stolen and used elsewhere, not the legitimate holder lying.
/// </para>
/// </remarks>
public static class DeviceKey
{
    /// <summary>
    /// Opens the existing device key, or creates one if this machine has never enrolled.
    /// </summary>
    /// <param name="softwareKeyPath">Where a software-held key is stored.</param>
    /// <returns>The signer and how the key is held.</returns>
    public static (ECDsa Key, KeyAttestation Attestation) OpenOrCreate(string softwareKeyPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(softwareKeyPath);

        return OperatingSystem.IsWindows()
            ? WindowsDeviceKey.OpenOrCreate(softwareKeyPath)
            : (UnixDeviceKey.OpenOrCreate(softwareKeyPath), KeyAttestation.Software);
    }

    /// <summary>Deletes the device key, so the machine can enrol afresh.</summary>
    /// <param name="softwareKeyPath">Where a software-held key is stored.</param>
    public static void Delete(string softwareKeyPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(softwareKeyPath);

        if (OperatingSystem.IsWindows())
        {
            WindowsDeviceKey.DeleteHardwareKey();
        }

        if (File.Exists(softwareKeyPath))
        {
            File.Delete(softwareKeyPath);
        }
    }

    /// <summary>
    /// Replaces the stored software key with a freshly rotated one.
    /// </summary>
    /// <remarks>
    /// <b>Called only AFTER Merlin has accepted the rotation.</b> Writing first would mean a refused
    /// rotation left the machine holding a key the server has never seen, which is the same dark
    /// device the old in-memory-only rotation produced — just reached from the other direction.
    /// Only reachable for a software-held key; a TPM key is refused earlier, because it cannot be
    /// replaced without downgrading the attestation.
    /// </remarks>
    /// <param name="softwareKeyPath">Where the software-held key is stored.</param>
    /// <param name="incoming">The newly generated key.</param>
    public static void Replace(string softwareKeyPath, ECDsa incoming)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(softwareKeyPath);
        ArgumentNullException.ThrowIfNull(incoming);

        if (OperatingSystem.IsWindows())
        {
            WindowsDeviceKey.WriteSoftwareKey(softwareKeyPath, incoming);
            return;
        }

        UnixDeviceKey.Write(softwareKeyPath, incoming);
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

    /// <summary>
    /// A sentence describing where the key is held, shown at enrolment.
    /// </summary>
    /// <remarks>
    /// Platform-specific because the reason for a software key differs: on Windows it means no
    /// usable TPM was found, which is a fact about that machine; on macOS and Linux it means this
    /// agent has no hardware key store yet, which is a fact about the agent. Telling a Mac owner
    /// their hardware lacks a secure element would be false.
    /// </remarks>
    /// <param name="attestation">How the key is held.</param>
    /// <returns>The explanation, or <c>null</c> when the key is in hardware.</returns>
    public static string? ExplainAttestation(KeyAttestation attestation)
    {
        if (attestation == KeyAttestation.Tpm)
        {
            return null;
        }

        return AgentPlatformInfo.Current switch
        {
            AgentOs.Windows =>
                "  No usable TPM was found, so the key is held in software. Merlin records this and "
                + "shows it against the device: a software key is weaker evidence because it can be "
                + "copied.",
            _ =>
                "  The key is held in a root-only file. This agent does not yet use the Secure "
                + "Enclave or a TPM on this platform, so the key could in principle be copied by "
                + "anyone with root. Merlin records this and shows it against the device.",
        };
    }
}
