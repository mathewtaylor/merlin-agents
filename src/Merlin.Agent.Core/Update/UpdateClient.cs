using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Merlin.Agent.Core.Contracts;
using Merlin.Agent.Core.Crypto;

namespace Merlin.Agent.Core.Update;

/// <summary>What Merlin said when asked whether this machine should be running something else.</summary>
public enum UpdateCheckStatus
{
    /// <summary>A version, an address and a hash. See <see cref="UpdateCheck.Advertisement"/>.</summary>
    Advertised,

    /// <summary>
    /// <c>204</c> — nothing to do. Already current, the ring is not due, or no version is
    /// configured. <b>This is the ORDINARY answer and is never an error.</b>
    /// </summary>
    NothingToDo,

    /// <summary>
    /// <c>404</c> — this Merlin does not offer updates. An older deployment, the agent surface
    /// switched off, or an installer pointed at the wrong tenant. <b>Degrade silently.</b>
    /// </summary>
    NotOffered,

    /// <summary>Merlin refused the request, or it could not be made at all.</summary>
    Refused,
}

/// <summary>The outcome of one update check.</summary>
/// <param name="Status">What Merlin said.</param>
/// <param name="Advertisement">The advertisement, when there was one.</param>
/// <param name="Detail">A sentence for the console.</param>
/// <param name="ClockOffsetSeconds">The clock correction, relearned where the server supplied one.</param>
public sealed record UpdateCheck(
    UpdateCheckStatus Status,
    AgentUpdateResponse? Advertisement,
    string Detail,
    long ClockOffsetSeconds);

/// <summary>
/// The signed client for <c>GET /api/agent/update</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>The same device key and the same <c>state.json</c> as the agent, from the shared state
/// directory.</b> There is no second enrolment and no second credential: the updater is another
/// process on the same machine running with the same privilege, and giving it its own identity
/// would double the number of things that can be stolen to impersonate one device.
/// </para>
/// <para>
/// <b>The canonical string is domain-separated by the literal label <c>update</c>, and the runtime
/// identifier is inside it.</b> An update-check signature can therefore never be presented as a
/// report signature, and nothing between this machine and Merlin can change which architecture's
/// binary is advertised.
/// </para>
/// <para>
/// <b>A refusal carries the same generic message every other agent route returns.</b> Do not try to
/// tell the causes apart — there is deliberately no oracle on that surface, and the real reason is
/// logged and audited where an administrator can see it.
/// </para>
/// </remarks>
public sealed class UpdateClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly ECDsa _key;
    private readonly bool _ownsHttp;

    /// <summary>Initialises a new instance of the <see cref="UpdateClient"/> class.</summary>
    /// <param name="serverUrl">The Merlin deployment's base address.</param>
    /// <param name="key">The device signing key.</param>
    /// <param name="agentVersion">The calling component's version.</param>
    /// <param name="clockOffsetSeconds">The correction learned by earlier runs.</param>
    public UpdateClient(string serverUrl, ECDsa key, string agentVersion, long clockOffsetSeconds)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serverUrl);
        ArgumentNullException.ThrowIfNull(key);

        _http = new HttpClient
        {
            BaseAddress = new Uri(serverUrl.TrimEnd('/') + "/", UriKind.Absolute),
            Timeout = TimeSpan.FromSeconds(60),

            // BOUNDED, BECAUSE THIS BODY IS NEITHER ALLOWLISTED NOR HASH-PINNED. The package
            // download has both and is streamed against a running total; this one comes from
            // whatever address the state file names, is buffered whole by default, and is read
            // into a string — two bytes of memory per byte on the wire — inside a process running
            // as SYSTEM or root. Every answer this endpoint gives is a few hundred bytes.
            // Exceeding it raises HttpRequestException, which the callers already treat as a
            // refused request, so it adds no new failure mode.
            MaxResponseContentBufferSize = 64 * 1024,
        };

        _http.DefaultRequestHeaders.UserAgent.Add(
            new ProductInfoHeaderValue("MerlinAgent", agentVersion));

        _key = key;
        _ownsHttp = true;
        AgentVersion = agentVersion;
        ClockOffsetSeconds = clockOffsetSeconds;
    }

    /// <summary>
    /// Initialises a new instance against a caller-supplied client.
    /// </summary>
    /// <remarks>
    /// <b>A test seam, on the same terms as <see cref="BinaryProbe"/>.</b> This class is the only
    /// implementation of the frozen wire contract in this repository — the canonical string, the
    /// headers, and the rule that <c>204</c> and <c>404</c> are ordinary answers rather than
    /// failures — and it had no tests at all, because it built its own transport and there was no
    /// way to answer it. The caller keeps ownership of what it passes: disposing a client somebody
    /// else is still using is a worse bug than the one this exists to catch.
    /// </remarks>
    /// <param name="http">The transport, already addressed at the deployment.</param>
    /// <param name="key">The device signing key.</param>
    /// <param name="agentVersion">The calling component's version.</param>
    /// <param name="clockOffsetSeconds">The correction learned by earlier runs.</param>
    public UpdateClient(HttpClient http, ECDsa key, string agentVersion, long clockOffsetSeconds)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(key);

        _http = http;
        _key = key;
        _ownsHttp = false;
        AgentVersion = agentVersion;
        ClockOffsetSeconds = clockOffsetSeconds;
    }

    /// <summary>The calling component's version, sent as a header.</summary>
    public string AgentVersion { get; }

    /// <summary>The clock offset, in seconds, applied when stamping a request.</summary>
    public long ClockOffsetSeconds { get; private set; }

    /// <summary>
    /// Asks Merlin what this device should be running.
    /// </summary>
    /// <param name="deviceId">This device's identifier.</param>
    /// <param name="runtimeIdentifier">This machine's runtime identifier.</param>
    /// <param name="now">This machine's current time, uncorrected.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>What Merlin said.</returns>
    public async Task<UpdateCheck> CheckAsync(
        Guid deviceId,
        string? runtimeIdentifier,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        for (int attempt = 0; attempt < 2; attempt++)
        {
            using HttpRequestMessage message = Build(deviceId, runtimeIdentifier, now);

            HttpResponseMessage response;

            try
            {
                response = await _http.SendAsync(message, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
            {
                return new UpdateCheck(
                    UpdateCheckStatus.Refused,
                    null,
                    $"Merlin could not be reached: {exception.Message}",
                    ClockOffsetSeconds);
            }

            using (response)
            {
                // 204 IS THE ORDINARY ANSWER. Already current, ring not due, or no version
                // configured. Treating it as a failure would have a healthy fleet reporting a
                // broken update every single day.
                if (response.StatusCode == HttpStatusCode.NoContent)
                {
                    return new UpdateCheck(
                        UpdateCheckStatus.NothingToDo,
                        null,
                        "Merlin has nothing to advertise to this device.",
                        ClockOffsetSeconds);
                }

                // 404 means this deployment does not offer updates — an older Merlin, or the agent
                // surface switched off. The machine keeps reporting exactly as before; there is
                // nothing wrong and nothing to say.
                if (response.StatusCode == HttpStatusCode.NotFound)
                {
                    return new UpdateCheck(
                        UpdateCheckStatus.NotOffered,
                        null,
                        "This Merlin deployment does not offer agent updates.",
                        ClockOffsetSeconds);
                }

                string content;

                try
                {
                    content = await response.Content.ReadAsStringAsync(cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
                {
                    // A CONNECTION DROPPED MID-BODY IS AN UNREACHABLE MERLIN, not a fault. The
                    // send above already says so; this read sat outside that reasoning, so the
                    // same outage produced a Refused on one line and an escaped exception — which
                    // the updater turns into a non-zero exit — on the next.
                    return new UpdateCheck(
                        UpdateCheckStatus.Refused,
                        null,
                        $"Merlin could not be reached: {exception.Message}",
                        ClockOffsetSeconds);
                }

                if (response.IsSuccessStatusCode)
                {
                    AgentUpdateResponse? advertisement = Deserialise(content);

                    // A VERSION, AN ADDRESS AND A HASH — all three, or it is not an answer. Only
                    // the version used to be checked, so a 200 carrying a blank endpoint or digest
                    // came back as Advertised; and when the target already matched, the note of
                    // what the OTHER component still needs was then overwritten with those blanks
                    // and cleared. Merlin goes quiet once the agent reports the desired version, so
                    // there is nothing to re-learn the note from: the two components stay split
                    // across versions, permanently and silently.
                    return advertisement is null
                        || string.IsNullOrWhiteSpace(advertisement.Version)
                        || string.IsNullOrWhiteSpace(advertisement.PackageEndpoint)
                        || string.IsNullOrWhiteSpace(advertisement.Sha256)
                        ? new UpdateCheck(
                            UpdateCheckStatus.Refused,
                            null,
                            "Merlin returned an advertisement we could not read.",
                            ClockOffsetSeconds)
                        : new UpdateCheck(
                            UpdateCheckStatus.Advertised,
                            advertisement,
                            $"Merlin advertises {advertisement.Version}.",
                            ClockOffsetSeconds);
                }

                if (TryLearnOffset(response.StatusCode, content, now, attempt))
                {
                    continue;
                }

                return new UpdateCheck(
                    UpdateCheckStatus.Refused,
                    null,
                    Describe(response.StatusCode, content),
                    ClockOffsetSeconds);
            }
        }

        return new UpdateCheck(
            UpdateCheckStatus.Refused,
            null,
            "The update check was refused twice, including after a clock correction.",
            ClockOffsetSeconds);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_ownsHttp)
        {
            _http.Dispose();
        }
    }

    private HttpRequestMessage Build(Guid deviceId, string? runtimeIdentifier, DateTimeOffset now)
    {
        string timestamp = AgentSignature.FormatTimestamp(now.AddSeconds(ClockOffsetSeconds));
        string nonce = AgentSignature.CreateNonce();
        string device = deviceId.ToString();

        string canonical = AgentSignature.CanonicalUpdate(device, timestamp, nonce, runtimeIdentifier);

        HttpRequestMessage message = new(HttpMethod.Get, "api/agent/update");

        message.Headers.Add(AgentSignature.DeviceIdHeader, device);
        message.Headers.Add(AgentSignature.TimestampHeader, timestamp);
        message.Headers.Add(AgentSignature.NonceHeader, nonce);
        message.Headers.Add(AgentSignature.SignatureHeader, DeviceKey.Sign(_key, canonical));
        message.Headers.Add(AgentSignature.AgentVersionHeader, AgentVersion);

        if (!string.IsNullOrWhiteSpace(runtimeIdentifier))
        {
            message.Headers.Add(AgentSignature.RuntimeIdentifierHeader, runtimeIdentifier);
        }

        return message;
    }

    /// <summary>
    /// Learns the server's clock from a refusal, exactly as the report path does — an unmanaged
    /// machine with a drifting clock must correct itself rather than be refused forever.
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
            refusal = JsonSerializer.Deserialize(content, UpdateJsonContext.Default.AgentRefusal);
        }
        catch (JsonException)
        {
            return false;
        }

        if (refusal is null || refusal.ServerTime <= 0)
        {
            return false;
        }

        long offset = (long)(DateTimeOffset.FromUnixTimeSeconds(refusal.ServerTime) - now).TotalSeconds;

        // MEASURED AGAINST THE CORRECTION ALREADY IN FORCE, never against zero. This asks one
        // question — would applying what the server just told us actually move the stamp? — and
        // asking it the other way is wrong in BOTH directions:
        //
        //  - a machine carrying a stale correction can never shed it. Once an hour of offset is
        //    stored, every request is stamped an hour from this machine's own clock, so the day the
        //    clock is FIXED that correction becomes the entire error. The server refuses, replies
        //    with a time that matches our raw clock exactly, and the absolute offset it implies is
        //    ZERO — which a "< 30" test reads as "not worth acting on". So it is refused again,
        //    for ever, and the value it needs to forget is the one it is being told to forget.
        //    That is a machine that silently stops reporting and stops updating, with no route back
        //    on the machine itself;
        //  - and a machine whose correction is RIGHT retries every refusal that was never about the
        //    clock, because its large, correct offset always clears the threshold — which is
        //    exactly the doubled load this guard was added to prevent.
        //
        // The difference answers both: near-zero means the stamp we already sent was what the
        // server would have wanted, so the clock is not why it was refused.
        if (Math.Abs(offset - ClockOffsetSeconds) < 30)
        {
            return false;
        }

        ClockOffsetSeconds = offset;
        return true;
    }

    private static AgentUpdateResponse? Deserialise(string content)
    {
        try
        {
            return JsonSerializer.Deserialize(content, UpdateJsonContext.Default.AgentUpdateResponse);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string Describe(HttpStatusCode statusCode, string content)
    {
        try
        {
            AgentRefusal? refusal = JsonSerializer.Deserialize(
                content, UpdateJsonContext.Default.AgentRefusal);

            if (refusal is { Message.Length: > 0 })
            {
                return refusal.Message;
            }
        }
        catch (JsonException)
        {
            // Fall through to the status code.
        }

        return $"Merlin refused the update check ({(int)statusCode}).";
    }
}

/// <summary>
/// Source-generated JSON context for the update surface. NativeAOT trims reflection-based
/// serialisation, so every type that crosses a serialiser needs an entry here.
/// </summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(AgentUpdateResponse))]
[JsonSerializable(typeof(AgentRefusal))]
public sealed partial class UpdateJsonContext : JsonSerializerContext;
