using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Merlin.Agent.Core.Contracts;
using Merlin.Agent.Core.Crypto;

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
/// <para>
/// <b>THE OFFSET IS ABSOLUTE, AND THE CALLER MUST HAND OVER A RAW INSTANT.</b> This client applies
/// <see cref="ClockOffsetSeconds"/> itself, so <c>now</c> is this machine's uncorrected clock and
/// what comes back out is the correction to store. A caller that pre-applies the stored offset AND
/// lets the client learn gets a <b>residual</b> — how wrong the already-corrected time still is —
/// which is right for the retry in flight and wrong the moment it is persisted, because every
/// reader treats the stored field as absolute.
/// </para>
/// <para>
/// It does not fail loudly. With <c>A</c> the true offset and <c>s</c> the stored one, persisting
/// the residual gives <c>s' = A - s</c>: a two-cycle that never converges, so a drifting machine
/// alternates between two wrong offsets for ever, paying a refusal and a retry on every single
/// run. It hid because the FIRST correction is taken against a raw instant and is therefore
/// genuinely absolute, so a freshly enrolled machine looks perfect. <c>UpdateClient</c> has always
/// worked this way; this client is the one that did not.
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
    /// <param name="clockOffsetSeconds">
    /// The correction this machine already knows it needs, from a previous run. Pass it and hand
    /// <c>now</c> over raw; do not pre-apply it. Zero for enrolment and for a move to a different
    /// deployment, which has its own clock and must be learned from scratch.
    /// </param>
    public ReportClient(string serverUrl, ECDsa key, string agentVersion, long clockOffsetSeconds = 0)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serverUrl);

        _http = new HttpClient
        {
            BaseAddress = new Uri(serverUrl.TrimEnd('/') + "/", UriKind.Absolute),
            Timeout = TimeSpan.FromSeconds(60),

            // BOUNDED, BECAUSE THIS BODY IS NEITHER ALLOWLISTED NOR HASH-PINNED. The package
            // download has both and is streamed against a running total; this one comes from
            // whatever address the state file names, is buffered whole by default, and is read
            // into a string — two bytes of memory per byte on the wire — inside a process running
            // as SYSTEM or root. Every answer this endpoint gives is a few hundred bytes.
            // Exceeding it raises HttpRequestException, which every caller here now turns into a
            // refused request rather than letting it escape, so it adds no new failure mode.
            MaxResponseContentBufferSize = 64 * 1024,
        };

        _http.DefaultRequestHeaders.UserAgent.Add(
            new ProductInfoHeaderValue("MerlinAgent", agentVersion));

        _key = key;
        _agentVersion = agentVersion;
        ClockOffsetSeconds = ClockSkew.Sanitise(clockOffsetSeconds);
    }

    /// <summary>
    /// The ABSOLUTE correction to add to this machine's clock, in seconds — as supplied, or as
    /// relearned from a refusal. This is the value to persist.
    /// </summary>
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

            HttpResponseMessage sent;

            try
            {
                sent = await _http.SendAsync(message).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
            {
                // AN UNREACHABLE MERLIN IS AN OUTCOME, not a crash. It reads as one to the person
                // typing `enrol` — who is standing in front of the machine, often on a network
                // that is the actual problem. The response-size cap also surfaces here, and a
                // captive portal's HTML login page is exactly what trips it: without this the
                // operator was told "Cannot write more bytes to the buffer than the configured
                // maximum buffer size: 65536" rather than that the server could not be reached.
                return (
                    new TransportResult(false, $"Merlin could not be reached: {exception.Message}", null),
                    null);
            }

            using HttpResponseMessage response = sent;
            string content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            if (response.IsSuccessStatusCode)
            {
                AgentEnrolResponse? enrolled = JsonSerializer.Deserialize(
                    content, WireJsonContext.Default.AgentEnrolResponse);

                return enrolled is null
                    ? (new TransportResult(false, "Merlin returned an enrolment response we could not read.", null), null)
                    : (new TransportResult(true, $"Enrolled as {enrolled.DeviceCode}.", enrolled.ServerTime), enrolled);
            }

            if (TryLearnOffset(response.StatusCode, content, now, attempt))
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

            // A REPORT THAT COULD NOT BE MADE IS A FAILED REPORT, NOT A THROWN ONE — and this is
            // the only place that can say so while still holding the JSON it built. When the caller
            // wrapped the call instead, it had nothing to hand back but the PREVIOUS payload, so
            // `merlin-agent status` showed a stale one while promising it shows exactly what this
            // machine tried to send. That promise is a transparency commitment, not a convenience.
            // Letting it throw is worse still: an outage then skips the update turn, which is the
            // one part of a run that needs no network at all.
            HttpResponseMessage response;

            try
            {
                response = await _http.SendAsync(message).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
            {
                return (
                    new TransportResult(false, $"Merlin could not be reached: {exception.Message}", null),
                    json);
            }

            using (response)
            {
                string content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                if (response.IsSuccessStatusCode)
                {
                    return (new TransportResult(true, "Report accepted.", null), json);
                }

                if (TryLearnOffset(response.StatusCode, content, now, attempt))
                {
                    continue;
                }

                return (new TransportResult(false, Describe(response.StatusCode, content), null), json);
            }
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

        HttpResponseMessage sent;

        try
        {
            sent = await _http.SendAsync(message).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            // As in EnrolAsync. The caller already answers a failure with "the existing key is
            // unchanged and this machine keeps reporting", which is the true and reassuring thing
            // to say about an outage — and is what an escaping exception replaced with a raw
            // transport message.
            return new TransportResult(
                false, $"Merlin could not be reached: {exception.Message}", null);
        }

        using HttpResponseMessage response = sent;
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
        DateTimeOffset now,
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

        // The RANGE of serverTime is ClockSkew's business, including the non-positive case — a
        // second copy of half a rule here is the drift shape the extraction exists to prevent.
        if (refusal is null)
        {
            return false;
        }

        // ONE RULE, SHARED. It was this twenty lines and this comment in two files, and the two
        // halves had already drifted once — one learning an absolute correction and the other a
        // residual, which produced a machine alternating between two wrong offsets for ever. Only
        // one of the two files sits in a project the test project can reference, so a duplicated
        // rule was also a rule that was half tested by construction.
        if (!ClockSkew.TryLearn(refusal.ServerTime, now, ClockOffsetSeconds, out long learned))
        {
            return false;
        }

        ClockOffsetSeconds = learned;
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
