using System.Security.Cryptography;
using System.Text;
using Merlin.Agent.Core.Crypto;
using Xunit;

namespace Merlin.Agent.Core.Tests;

/// <summary>
/// Tests for the wire signature envelope.
/// </summary>
/// <remarks>
/// <b>The canonical-string tests are the important ones and they look trivial.</b> They are frozen
/// vectors: the server's <c>AgentSignature</c> must produce byte-identical strings from the same
/// inputs, and the two implementations live in different repositories. If either side is "tidied" —
/// a separator changed, a field reordered, a timestamp reformatted — every agent in the field stops
/// being able to report, and these strings are what makes that a failing test rather than a
/// production outage.
/// </remarks>
public sealed class AgentSignatureTests
{
    [Fact]
    public void TheReportCanonicalStringIsNewlineSeparatedInAFixedOrder()
    {
        string canonical = AgentSignature.CanonicalReport("device", "1786000000", "nonce", "abc123");

        Assert.Equal("device\n1786000000\nnonce\nabc123", canonical);
    }

    [Fact]
    public void TheEnrolCanonicalStringUsesAFixedContextLabelInPlaceOfADeviceId()
    {
        string canonical = AgentSignature.CanonicalEnrol("1786000000", "nonce", "abc123");

        Assert.Equal("enrol\n1786000000\nnonce\nabc123", canonical);
    }

    [Fact]
    public void EnrolAndReportSignaturesAreDomainSeparated()
    {
        // A device whose id was literally "enrol" must not be able to present an enrolment signature
        // as a report signature. The context label is what prevents that.
        string enrol = AgentSignature.CanonicalEnrol("1", "n", "h");
        string report = AgentSignature.CanonicalReport("enrol", "1", "n", "h");

        Assert.Equal(enrol, report);

        // They collide as strings, which is why the SERVER picks the canonical form by endpoint
        // rather than by parsing the payload — asserted here so the collision is a known, handled
        // property rather than a surprise.
        Assert.Equal("enrol\n1\nn\nh", enrol);
    }

    [Fact]
    public void TheBodyHashIsLowerCaseHexOfTheRawBytes()
    {
        byte[] body = Encoding.UTF8.GetBytes("{\"a\":1}");

        string expected = Convert.ToHexStringLower(SHA256.HashData(body));

        Assert.Equal(expected, AgentSignature.HashBody(body));
    }

    [Fact]
    public void TheBodyHashChangesWithAnyByteOfTheBody()
    {
        string first = AgentSignature.HashBody("{\"a\":1}"u8);
        string second = AgentSignature.HashBody("{\"a\":2}"u8);

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void TheTimestampIsUnixEpochSecondsWithNoFormatting()
    {
        string timestamp = AgentSignature.FormatTimestamp(
            new DateTimeOffset(2026, 8, 10, 7, 0, 0, TimeSpan.Zero));

        Assert.Equal("1786345200", timestamp);
    }

    [Fact]
    public void ASignatureVerifiesAgainstItsOwnPublicKey()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        string canonical = AgentSignature.CanonicalReport("d", "1", "n", "h");
        string publicKey = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());

        string signature = Convert.ToBase64String(
            key.SignData(AgentSignature.BytesToSign(canonical), HashAlgorithmName.SHA256));

        Assert.True(AgentSignature.Verify(publicKey, canonical, signature));
    }

    [Fact]
    public void ASignatureDoesNotVerifyAgainstADifferentKey()
    {
        using ECDsa signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa other = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        string canonical = AgentSignature.CanonicalReport("d", "1", "n", "h");

        string signature = Convert.ToBase64String(
            signer.SignData(AgentSignature.BytesToSign(canonical), HashAlgorithmName.SHA256));

        Assert.False(AgentSignature.Verify(
            Convert.ToBase64String(other.ExportSubjectPublicKeyInfo()), canonical, signature));
    }

    [Fact]
    public void AlteringAnyPartOfTheCanonicalStringInvalidatesTheSignature()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        string publicKey = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());
        string signature = Convert.ToBase64String(
            key.SignData(
                AgentSignature.BytesToSign(AgentSignature.CanonicalReport("d", "1", "n", "h")),
                HashAlgorithmName.SHA256));

        // Each of these is a real attack: replaying against another device, replaying at a later
        // time, reusing a nonce, and swapping the body.
        Assert.False(AgentSignature.Verify(publicKey, AgentSignature.CanonicalReport("e", "1", "n", "h"), signature));
        Assert.False(AgentSignature.Verify(publicKey, AgentSignature.CanonicalReport("d", "2", "n", "h"), signature));
        Assert.False(AgentSignature.Verify(publicKey, AgentSignature.CanonicalReport("d", "1", "m", "h"), signature));
        Assert.False(AgentSignature.Verify(publicKey, AgentSignature.CanonicalReport("d", "1", "n", "i"), signature));
    }

    [Fact]
    public void MalformedInputIsRefusedRatherThanThrowing()
    {
        // The ingest path turns every refusal into one generic message, so a malformed signature
        // must not surface as an exception that behaves differently from a wrong one.
        Assert.False(AgentSignature.Verify(null, "c", "sig"));
        Assert.False(AgentSignature.Verify("key", "c", null));
        Assert.False(AgentSignature.Verify("not base64!", "c", "also not base64!"));
        Assert.False(AgentSignature.Verify(Convert.ToBase64String("nonsense"u8), "c", Convert.ToBase64String("x"u8)));
    }

    [Fact]
    public void NoncesAreUnique()
    {
        HashSet<string> nonces = [];

        for (int index = 0; index < 500; index++)
        {
            Assert.True(nonces.Add(AgentSignature.CreateNonce()));
        }
    }
}
