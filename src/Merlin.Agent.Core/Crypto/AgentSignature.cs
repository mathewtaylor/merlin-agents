using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Merlin.Agent.Core.Crypto;

/// <summary>
/// The wire signature envelope — header names, canonical string construction and body hashing.
/// </summary>
/// <remarks>
/// <para>
/// <b>This file is the client half of a contract, and its server half is
/// <c>Merlin.Endpoints.Application.Services.AgentSignature</c>.</b> The two must agree byte for
/// byte. They are deliberately small and free of dependencies so that agreement is checkable by
/// reading them side by side, and <c>docs/protocol.md</c> specifies what they implement.
/// </para>
/// <para>
/// <b>The signature covers a hash of the RAW REQUEST BYTES.</b> The agent hashes exactly the bytes
/// it is about to put on the wire, and the server hashes exactly the bytes it received. No JSON
/// canonicalisation is involved anywhere: any scheme that re-encodes a payload before hashing opens
/// a gap between what was signed and what will be acted on, which is a well-worn source of
/// signature-bypass bugs.
/// </para>
/// <para>
/// <b>The timestamp is signed as the literal characters sent in the header</b>, as Unix epoch
/// seconds. Signing a re-rendered timestamp would let two correct implementations disagree about
/// whether an instant is <c>...T07:00:00Z</c> or <c>...T07:00:00.000Z</c> and fail a signature for
/// nobody's fault.
/// </para>
/// </remarks>
public static class AgentSignature
{
    /// <summary>Header carrying the reporting device's identifier.</summary>
    public const string DeviceIdHeader = "Merlin-Device-Id";

    /// <summary>Header carrying the request instant, as Unix epoch seconds.</summary>
    public const string TimestampHeader = "Merlin-Timestamp";

    /// <summary>Header carrying the single-use nonce.</summary>
    public const string NonceHeader = "Merlin-Nonce";

    /// <summary>Header carrying the Base64 IEEE P1363 signature.</summary>
    public const string SignatureHeader = "Merlin-Signature";

    /// <summary>Header carrying this agent's version.</summary>
    public const string AgentVersionHeader = "Merlin-Agent-Version";

    /// <summary>
    /// Header carrying the caller's .NET runtime identifier — <c>win-x64</c>, <c>linux-arm64</c>.
    /// </summary>
    /// <remarks>
    /// <b>Sent because Merlin does not know it.</b> A device row stores the PLATFORM, which says
    /// Windows or macOS or Linux and not which architecture — and there is one binary per
    /// architecture, each with its own hash.
    /// </remarks>
    public const string RuntimeIdentifierHeader = "Merlin-Agent-Rid";

    private const string EnrolContext = "enrol";

    private const string UpdateContext = "update";

    /// <summary>Computes the lower-case hex SHA-256 of a request body.</summary>
    /// <param name="body">The exact bytes to be sent.</param>
    /// <returns>Lower-case hex digest.</returns>
    public static string HashBody(ReadOnlySpan<byte> body) =>
        Convert.ToHexStringLower(SHA256.HashData(body));

    /// <summary>Builds the canonical string signed by a report or rotation request.</summary>
    /// <param name="deviceId">The literal device-id header value.</param>
    /// <param name="timestamp">The literal timestamp header value.</param>
    /// <param name="nonce">The literal nonce header value.</param>
    /// <param name="bodyHash">The body hash.</param>
    /// <returns>The canonical string.</returns>
    public static string CanonicalReport(
        string deviceId,
        string timestamp,
        string nonce,
        string bodyHash) =>
        string.Join('\n', deviceId, timestamp, nonce, bodyHash);

    /// <summary>
    /// Builds the canonical string signed by an enrolment request.
    /// </summary>
    /// <remarks>
    /// A fixed context label stands where the device id would be, because there is no device yet. It
    /// also domain-separates the two signature kinds so an enrolment signature can never be
    /// presented as a report signature.
    /// </remarks>
    /// <param name="timestamp">The literal timestamp header value.</param>
    /// <param name="nonce">The literal nonce header value.</param>
    /// <param name="bodyHash">The body hash.</param>
    /// <returns>The canonical string.</returns>
    public static string CanonicalEnrol(string timestamp, string nonce, string bodyHash) =>
        string.Join('\n', EnrolContext, timestamp, nonce, bodyHash);

    /// <summary>
    /// Builds the canonical string signed by an UPDATE-CHECK request.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>No body hash, because there is no body</b> — this is a <c>GET</c>. A fixed context label
    /// leads, exactly as it does for enrolment, so an update-check signature is domain-separated
    /// from a report signature and neither can be presented as the other.
    /// </para>
    /// <para>
    /// <b>The runtime identifier is SIGNED, not merely sent.</b> It decides which architecture's
    /// binary is advertised, so leaving it outside the signature would let anything between this
    /// machine and Merlin change which package it is pointed at. The hash check on the download
    /// would catch it, but a signature covering every input to the answer is cheaper than reasoning
    /// about what the next check happens to catch.
    /// </para>
    /// </remarks>
    /// <param name="deviceId">The literal device-id header value.</param>
    /// <param name="timestamp">The literal timestamp header value.</param>
    /// <param name="nonce">The literal nonce header value.</param>
    /// <param name="runtimeIdentifier">The literal runtime-identifier header value.</param>
    /// <returns>The canonical string.</returns>
    public static string CanonicalUpdate(
        string deviceId,
        string timestamp,
        string nonce,
        string? runtimeIdentifier) =>
        string.Join('\n', UpdateContext, deviceId, timestamp, nonce, runtimeIdentifier ?? string.Empty);

    /// <summary>Renders an instant as the literal timestamp header value.</summary>
    /// <param name="instant">The instant.</param>
    /// <returns>Unix epoch seconds, invariant.</returns>
    public static string FormatTimestamp(DateTimeOffset instant) =>
        instant.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);

    /// <summary>Generates a fresh 128-bit nonce.</summary>
    /// <returns>Base64Url-encoded nonce.</returns>
    public static string CreateNonce() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(16))
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');

    /// <summary>Encodes a canonical string for signing.</summary>
    /// <param name="canonical">The canonical string.</param>
    /// <returns>Its UTF-8 bytes.</returns>
    public static byte[] BytesToSign(string canonical) => Encoding.UTF8.GetBytes(canonical);

    /// <summary>
    /// Verifies a signature against a public key. Present so a test can prove the agent's signing
    /// and the server's verification agree without either side being mocked.
    /// </summary>
    /// <param name="publicKeyBase64">Base64 SPKI DER public key.</param>
    /// <param name="canonical">The canonical string that was signed.</param>
    /// <param name="signatureBase64">Base64 IEEE P1363 signature.</param>
    /// <returns><c>true</c> when the signature verifies.</returns>
    public static bool Verify(string? publicKeyBase64, string canonical, string? signatureBase64)
    {
        if (string.IsNullOrWhiteSpace(publicKeyBase64) || string.IsNullOrWhiteSpace(signatureBase64))
        {
            return false;
        }

        byte[] publicKey;
        byte[] signature;

        try
        {
            publicKey = Convert.FromBase64String(publicKeyBase64);
            signature = Convert.FromBase64String(signatureBase64);
        }
        catch (FormatException)
        {
            return false;
        }

        try
        {
            using ECDsa ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(publicKey, out _);

            return ecdsa.VerifyData(BytesToSign(canonical), signature, HashAlgorithmName.SHA256);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
}
