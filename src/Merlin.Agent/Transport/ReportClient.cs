using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Merlin.Agent.Core.Contracts;
using Merlin.Agent.Core.Crypto;
using Merlin.Agent.Crypto;

namespace Merlin.Agent.Transport;

/// <summary>The outcome of one request to Merlin.</summary>
/// <param name="Succeeded">Whether Merlin accepted it.</param>
/// <param name="Detail">Human-readable detail for the console.</param>
/// <param name="ServerTime">The server's clock, where it told us.</param>
public sealed record TransportResult(bool Succeeded, string Detail, DateTimeOffset? ServerTime);

/// <summary>
/// Signs and posts everything the agent sends.
/// </summary>
/// <remarks>
/// <para>
/// <b>The body is serialised ONCE, and those exact bytes are both hashed and sent.</b> Serialising
/// twice — once to hash, once to send — would be the classic way to break a signature scheme, since
/// nothing guarantees two serialisations are byte-identical.
/// </para>
/// <para>
/// <b>Clock skew is corrected rather than fatal.</b> Unmanaged machines drift, and Merlin returns
/// its own time when it refuses a request. The agent applies the offset and retries once, which
/// turns "this laptop can never report" into a self-healing hiccup. The offset is persisted so the
/// next run starts correct.
/// </para>
/// </remarks>
public sealed class ReportClient : IDisposable
{
    private static readonly JsonSerializerOptions _json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        TypeInfoResolver = WireJsonContext.Default,
    };

    private readonly HttpClient _http;
    private readonly ECDsa _key;
    private readonly string _agentVersion;

    /// <summary>Initialises a new instance of the <see cref="ReportClient"/> class.</summary>
    /// <param name="serverUrl">The Merlin deployment's base address.</param>
    /// <param name="key">The device signing key.</param>
    /// <param name="agentVersion">This agent's version.</param>
    public ReportClient(string serverUrl, ECDsa key, string agentVersion)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serverUrl);

        _http = new HttpClient
        {
            BaseAddress = new Uri(serverUrl.TrimEnd('/') + "/", UriKind.Absolute),
            Timeout = TimeSpan.FromSeconds(60),
        };

        _http.DefaultRequestHeaders.UserAgent.Add(
            new ProductInfoHeaderValue("MerlinAgent", agentVersion));

        _key = key;
        _agentVersion = agentVersion;
    }

    /// <summary>The clock offset, in seconds, learned from a refused request.</summary>
    public long ClockOffsetSeconds { get; private set; }

    /// <summary>Enrols this machine.</summary>
    /// <param name="request">The enrolment request.</param>
    /// <param name="enrolmentKey">The bearer enrolment key.</param>
    /// <param name="now">This machine's current time.</param>
    /// <returns>The response, or a failure.</returns>
    public async Task<(TransportResult Result, AgentEnrolResponse? Response)> EnrolAsync(
        AgentEnrolRequest request,
        string enrolmentKey,
        DateTimeOffset now)
    {
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(request, WireJsonContext.Default.AgentEnrolRequest);

        for (int attempt = 0; attempt < 2; attempt++)
        {
            using HttpRequestMessage message = Build("api/agent/enrol", body, deviceId: null, now);
            message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", enrolmentKey);

            using HttpResponseMessage response = await _http.SendAsync(message).ConfigureAwait(false);
            string content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            if (response.IsSuccessStatusCode)
            {
                AgentEnrolResponse? enrolled = JsonSerializer.Deserialize(
                    content, WireJsonContext.Default.AgentEnrolResponse);

                return enrolled is null
                    ? (new TransportResult(false, "Merlin returned an enrolment response we could not read.", null), null)
                    : (new TransportResult(true, $"Enrolled as {enrolled.DeviceCode}.", enrolled.ServerTime), enrolled);
            }

            if (TryLearnOffset(response.StatusCode, content, ref now, attempt))
            {
                continue;
            }

            return (new TransportResult(false, Describe(response.StatusCode, content), null), null);
        }

        return (new TransportResult(false, "Enrolment was refused twice, including after a clock correction.", null), null);
    }

    /// <summary>Posts one posture report.</summary>
    /// <param name="payload">The payload.</param>
    /// <param name="deviceId">This device's identifier.</param>
    /// <param name="now">This machine's current time.</param>
    /// <returns>The outcome, and the exact JSON sent.</returns>
    public async Task<(TransportResult Result, string Json)> ReportAsync(
        AgentReportPayload payload,
        Guid deviceId,
        DateTimeOffset now)
    {
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(payload, WireJsonContext.Default.AgentReportPayload);
        string json = Encoding.UTF8.GetString(body);

        for (int attempt = 0; attempt < 2; attempt++)
        {
            using HttpRequestMessage message = Build("api/agent/report", body, deviceId, now);
            using HttpResponseMessage response = await _http.SendAsync(message).ConfigureAwait(false);
            string content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            if (response.IsSuccessStatusCode)
            {
                return (new TransportResult(true, "Report accepted.", null), json);
            }

            if (TryLearnOffset(response.StatusCode, content, ref now, attempt))
            {
                continue;
            }

            return (new TransportResult(false, Describe(response.StatusCode, content), null), json);
        }

        return (new TransportResult(false, "The report was refused twice, including after a clock correction.", null), json);
    }

    /// <summary>Rotates this device's signing key, authenticated by the outgoing key.</summary>
    /// <param name="request">The rotation request.</param>
    /// <param name="deviceId">This device's identifier.</param>
    /// <param name="now">This machine's current time.</param>
    /// <returns>The outcome.</returns>
    public async Task<TransportResult> RotateAsync(
        AgentRotateRequest request,
        Guid deviceId,
        DateTimeOffset now)
    {
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(request, WireJsonContext.Default.AgentRotateRequest);

        using HttpRequestMessage message = Build("api/agent/rotate", body, deviceId, now);
        using HttpResponseMessage response = await _http.SendAsync(message).ConfigureAwait(false);
        string content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        return response.IsSuccessStatusCode
            ? new TransportResult(true, "Key rotated.", null)
            : new TransportResult(false, Describe(response.StatusCode, content), null);
    }

    /// <inheritdoc />
    public void Dispose() => _http.Dispose();

    private HttpRequestMessage Build(string path, byte[] body, Guid? deviceId, DateTimeOffset now)
    {
        DateTimeOffset stamped = now.AddSeconds(ClockOffsetSeconds);
        string timestamp = AgentSignature.FormatTimestamp(stamped);
        string nonce = AgentSignature.CreateNonce();
        string bodyHash = AgentSignature.HashBody(body);

        string canonical = deviceId is null
            ? AgentSignature.CanonicalEnrol(timestamp, nonce, bodyHash)
            : AgentSignature.CanonicalReport(deviceId.Value.ToString(), timestamp, nonce, bodyHash);

        HttpRequestMessage message = new(HttpMethod.Post, path)
        {
            Content = new ByteArrayContent(body),
        };

        message.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

        if (deviceId is not null)
        {
            message.Headers.Add(AgentSignature.DeviceIdHeader, deviceId.Value.ToString());
        }

        message.Headers.Add(AgentSignature.TimestampHeader, timestamp);
        message.Headers.Add(AgentSignature.NonceHeader, nonce);
        message.Headers.Add(AgentSignature.SignatureHeader, DeviceKey.Sign(_key, canonical));
        message.Headers.Add(AgentSignature.AgentVersionHeader, _agentVersion);

        return message;
    }

    /// <summary>
    /// Learns the server's clock from a refusal, so a machine with a wrong clock corrects itself
    /// rather than failing forever.
    /// </summary>
    private bool TryLearnOffset(
        HttpStatusCode statusCode,
        string content,
        ref DateTimeOffset now,
        int attempt)
    {
        if (attempt > 0 || statusCode != HttpStatusCode.BadRequest)
        {
            return false;
        }

        AgentRefusal? refusal;

        try
        {
            refusal = JsonSerializer.Deserialize(content, WireJsonContext.Default.AgentRefusal);
        }
        catch (JsonException)
        {
            return false;
        }

        if (refusal is null || refusal.ServerTime <= 0)
        {
            return false;
        }

        DateTimeOffset serverTime = DateTimeOffset.FromUnixTimeSeconds(refusal.ServerTime);
        long offset = (long)(serverTime - now).TotalSeconds;

        // Only worth retrying when the clock is actually the likely cause. A one-second difference
        // is not why a request was refused, and retrying every refusal would double the load a
        // genuinely misconfigured fleet puts on the server.
        if (Math.Abs(offset) < 30)
        {
            return false;
        }

        ClockOffsetSeconds = offset;
        return true;
    }

    private static string Describe(HttpStatusCode statusCode, string content)
    {
        if (statusCode == HttpStatusCode.NotFound)
        {
            return "This Merlin deployment does not have the agent surface switched on.";
        }

        try
        {
            AgentRefusal? refusal = JsonSerializer.Deserialize(content, WireJsonContext.Default.AgentRefusal);

            if (refusal is { Message.Length: > 0 })
            {
                return refusal.Message;
            }
        }
        catch (JsonException)
        {
            // Fall through to the status code.
        }

        return $"Merlin refused the request ({(int)statusCode}).";
    }
}

/// <summary>Source-generated JSON context for the wire contracts.</summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(AgentEnrolRequest))]
[JsonSerializable(typeof(AgentEnrolResponse))]
[JsonSerializable(typeof(AgentRotateRequest))]
[JsonSerializable(typeof(AgentReportPayload))]
[JsonSerializable(typeof(AgentRefusal))]
public sealed partial class WireJsonContext : JsonSerializerContext;
