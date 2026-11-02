// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace IyaSec.Gnap;

public interface ISignalsLog
{
    void Info(string message);
    void Warn(string message);
    void Error(string message);
}

public sealed class SsfRequest
{
    public string Method { get; init; }
    public string Url { get; init; }
    public string Body { get; init; }
}

public sealed class SignalEvent
{
    public string Type { get; set; }
    public JsonNode Payload { get; set; }
    public Dictionary<string, string> Subject { get; set; }
    public string Jti { get; set; }
    public List<string> Sessions { get; set; }
    public bool Ended { get; set; }
    public double? Iat { get; set; }
    public string Txn { get; set; }
}

public sealed class ReceiverOpt
{
    public TlsOpt Tls { get; init; }
    public Func<SsfRequest, Dictionary<string, string>> Headers { get; init; }
    public IReadOnlyList<string> EventsRequested { get; init; }
    public IReadOnlyList<string> EndOn { get; init; }
    public string Description { get; init; }
    public int PollIntervalMs { get; init; }
    public int MaxEvents { get; init; }
    public ISignalsLog Log { get; init; }
}

public sealed class SignalsReceiver
{
    const string PollMethod = "urn:ietf:rfc:8936";
    static readonly Regex SignatureRetry = new(@"publishes no|signing key|does not verify", RegexOptions.Compiled);

    public JsonObject Stream { get; private set; }

    readonly string transmitter;
    readonly TlsOpt tls;
    readonly Func<SsfRequest, Dictionary<string, string>> headers;
    readonly List<string> events;
    readonly List<string> endOn;
    readonly string description;
    readonly int interval;
    readonly int maxEvents;
    readonly ISignalsLog log;
    readonly Action<IReadOnlyList<string>, SignalEvent> onEnd;
    readonly MemoryIndex index = new();
    readonly object mu = new();
    readonly object gate = new();
    JsonObject config;
    List<JsonObject> keys = new();
    double keysAt;
    bool running;
    List<string> ack = new();
    Dictionary<string, Dictionary<string, string>> errs = new();
    readonly Dictionary<string, List<Action<SignalEvent>>> handlers = new();
    Flight flight;
    Thread worker;
    ManualResetEventSlim entered;
    ManualResetEventSlim finished;

    sealed class Flight
    {
        public ManualResetEventSlim Done { get; } = new(false);
        public bool More;
        public Exception Err;
    }

    sealed class PrintLog : ISignalsLog
    {
        public void Info(string message) => Console.WriteLine(message);
        public void Warn(string message) => Console.WriteLine(message);
        public void Error(string message) => Console.WriteLine(message);
    }

    public SignalsReceiver(string transmitter, Action<IReadOnlyList<string>, SignalEvent> onEnd, ReceiverOpt opt)
    {
        if (onEnd == null) throw new GnapException("config", "onEndSessions is required");
        if (string.IsNullOrEmpty(transmitter) || (!transmitter.StartsWith("https://") && !transmitter.StartsWith("http://")))
            throw new GnapException("config", "transmitter must be an http(s) URL");
        opt ??= new ReceiverOpt();
        this.transmitter = transmitter.TrimEnd('/');
        tls = opt.Tls;
        headers = opt.Headers;
        events = opt.EventsRequested == null ? Events.DefaultRequested.ToList() : opt.EventsRequested.ToList();
        endOn = opt.EndOn == null ? Events.DefaultEnding.ToList() : opt.EndOn.ToList();
        description = opt.Description ?? "";
        interval = opt.PollIntervalMs == 0 ? 5000 : opt.PollIntervalMs;
        maxEvents = opt.MaxEvents == 0 ? 50 : opt.MaxEvents;
        log = opt.Log ?? new PrintLog();
        this.onEnd = onEnd;
    }

    public void Track(TrackedSession session)
    {
        lock (mu) index.Add(session);
    }

    public void Untrack(string localId)
    {
        lock (mu) index.Remove(localId);
    }

    public SignalsReceiver On(string eventType, Action<SignalEvent> handler)
    {
        lock (mu)
        {
            if (!handlers.TryGetValue(eventType, out var list)) handlers[eventType] = list = new List<Action<SignalEvent>>();
            list.Add(handler);
        }
        return this;
    }

    public void Start()
    {
        lock (mu)
        {
            if (running) return;
        }
        Discover();
        Jwks(true);
        EnsureStream();
        var delivery = JsonUtil.Obj(Stream?["delivery"]);
        var endpoint = JsonUtil.Str(delivery?["endpoint_url"]);
        if (string.IsNullOrEmpty(endpoint)) throw new GnapException("ssf", "the stream has no poll endpoint_url");
        var delivered = JsonUtil.Arr(Stream["events_delivered"]);
        log.Info("ssf: polling stream " + JsonUtil.Str(Stream["stream_id"]) + " at " + endpoint + ", delivering " + (delivered?.Count ?? 0) + " event type(s)");
        var started = new ManualResetEventSlim(false);
        var done = new ManualResetEventSlim(false);
        lock (mu)
        {
            running = true;
            entered = started;
            finished = done;
        }
        worker = new Thread(Loop) { IsBackground = true, Name = "ssf-poll" };
        worker.Start();
        started.Wait();
    }

    public void Stop()
    {
        ManualResetEventSlim done;
        lock (mu)
        {
            done = finished;
            running = false;
            if (done == null) return;
        }
        done.Wait();
    }

    public bool PollOnce()
    {
        Flight mine = null;
        Flight current;
        lock (gate)
        {
            if (flight != null) current = flight;
            else mine = flight = current = new Flight();
        }
        if (mine == null)
        {
            current.Done.Wait();
            if (current.Err != null) throw current.Err;
            return current.More;
        }
        try { mine.More = PollNow(); }
        catch (Exception err) { mine.Err = err; }
        lock (gate)
        {
            if (flight == mine) flight = null;
        }
        mine.Done.Set();
        if (mine.Err != null) throw mine.Err;
        return mine.More;
    }

    public void Verify(string state)
    {
        var endpoint = JsonUtil.Str(config?["verification_endpoint"]);
        if (string.IsNullOrEmpty(endpoint)) throw new GnapException("ssf", "the transmitter publishes no verification_endpoint");
        var body = new JsonObject { ["stream_id"] = JsonUtil.Str(Stream?["stream_id"]) };
        if (!string.IsNullOrEmpty(state)) body["state"] = state;
        var (status, _) = Call("POST", endpoint, body);
        if (status != 200 && status != 204) throw new GnapException("ssf", "verification answered " + status);
    }

    void Loop()
    {
        var first = true;
        try
        {
            while (true)
            {
                bool live;
                lock (mu) live = running;
                if (!live)
                {
                    if (first) entered.Set();
                    return;
                }
                if (first)
                {
                    first = false;
                    entered.Set();
                }
                var delay = interval;
                try
                {
                    if (PollOnce()) delay = 0;
                }
                catch (Exception err)
                {
                    log.Warn("ssf: poll failed: " + err.Message);
                    delay = interval * 4;
                    if (delay > 60000) delay = 60000;
                }
                lock (mu) live = running;
                if (!live) return;
                var left = delay;
                while (left > 0)
                {
                    var slice = Math.Min(left, 50);
                    Thread.Sleep(slice);
                    left -= slice;
                    lock (mu) live = running;
                    if (!live) return;
                }
            }
        }
        finally
        {
            finished.Set();
        }
    }

    (int Status, string Body) Call(string method, string rawUrl, JsonNode body)
    {
        string text = body == null ? null : JsonUtil.Dump(body);
        var sent = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["accept"] = "application/json" };
        if (headers != null)
        {
            var extra = headers(new SsfRequest { Method = method, Url = rawUrl, Body = text ?? "" });
            if (extra != null)
                foreach (var pair in extra) sent[pair.Key] = pair.Value;
        }
        if (text != null && !sent.ContainsKey("content-type")) sent["content-type"] = "application/json";
        var answer = Http.Send(rawUrl, method, sent, text, tls, "ssf");
        return (answer.Status, answer.Body);
    }

    void Discover()
    {
        var urls = Urls.WellKnown(transmitter, "ssf-configuration");
        GnapException last = new("ssf", "no transmitter configuration at " + string.Join(" or ", urls));
        for (var i = 0; i < urls.Count; i++)
        {
            var (status, raw) = Call("GET", urls[i], null);
            if (status == 404 && i != urls.Count - 1) continue;
            JsonObject doc = null;
            try { doc = JsonUtil.Obj(JsonUtil.Parse(raw)); }
            catch { doc = null; }
            if (status != 200 || doc == null || string.IsNullOrEmpty(JsonUtil.Str(doc["configuration_endpoint"])) || string.IsNullOrEmpty(JsonUtil.Str(doc["jwks_uri"])))
            {
                last = new GnapException("ssf", urls[i] + " answered " + status + " without a usable transmitter configuration");
                continue;
            }
            var methods = JsonUtil.Arr(doc["delivery_methods_supported"]);
            if (methods != null && methods.Count > 0 && !methods.Any(item => JsonUtil.Str(item) == PollMethod))
                throw new GnapException("ssf", "the transmitter does not offer poll delivery (RFC 8936)");
            config = doc;
            return;
        }
        throw last;
    }

    List<JsonObject> Jwks(bool force)
    {
        if (!force && keys.Count > 0 && DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - keysAt < 3600000) return keys;
        var (status, raw) = Call("GET", JsonUtil.Str(config["jwks_uri"]), null);
        JsonObject doc = null;
        try { doc = JsonUtil.Obj(JsonUtil.Parse(raw)); }
        catch { doc = null; }
        var list = JsonUtil.Arr(doc?["keys"]);
        if (status != 200 || list == null) throw new GnapException("ssf", "the transmitter's JWKS answered " + status);
        var next = list.Select(JsonUtil.Obj).Where(o => o != null).ToList();
        keys = next;
        keysAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        return keys;
    }

    void EnsureStream()
    {
        var endpoint = JsonUtil.Str(config["configuration_endpoint"]);
        var (status, raw) = Call("GET", endpoint, null);
        if (status == 200)
        {
            JsonNode parsed = null;
            try { parsed = JsonUtil.Parse(raw); }
            catch { parsed = null; }
            var streams = new List<JsonNode>();
            if (JsonUtil.Arr(parsed) is JsonArray list) foreach (var item in list) streams.Add(item);
            else if (parsed != null) streams.Add(parsed);
            foreach (var item in streams)
            {
                var stream = JsonUtil.Obj(item);
                if (stream == null || string.IsNullOrEmpty(JsonUtil.Str(stream["stream_id"]))) continue;
                var delivery = JsonUtil.Obj(stream["delivery"]);
                if (JsonUtil.Str(delivery?["method"]) == PollMethod)
                {
                    Stream = stream;
                    return;
                }
            }
        }
        else if (status != 404)
            throw new GnapException("ssf", "listing the streams at " + endpoint + " answered " + status + ": " + Clip(raw, 300));
        var payload = new JsonObject
        {
            ["delivery"] = new JsonObject { ["method"] = PollMethod },
            ["events_requested"] = new JsonArray(events.Select(item => (JsonNode)item).ToArray())
        };
        if (!string.IsNullOrEmpty(description)) payload["description"] = description;
        (status, raw) = Call("POST", endpoint, payload);
        JsonObject created = null;
        try { created = JsonUtil.Obj(JsonUtil.Parse(raw)); }
        catch { created = null; }
        if ((status != 200 && status != 201) || created == null || string.IsNullOrEmpty(JsonUtil.Str(created["stream_id"])))
            throw new GnapException("ssf", "creating a stream at " + endpoint + " answered " + status + ": " + Clip(raw, 300));
        Stream = created;
    }

    bool PollNow()
    {
        var delivery = JsonUtil.Obj(Stream["delivery"]);
        var rawUrl = JsonUtil.Str(delivery?["endpoint_url"]);
        List<string> pendingAck;
        Dictionary<string, Dictionary<string, string>> pendingErrs;
        lock (mu)
        {
            pendingAck = ack.ToList();
            ack = new List<string>();
            pendingErrs = errs;
            errs = new Dictionary<string, Dictionary<string, string>>();
        }
        var body = new JsonObject { ["maxEvents"] = maxEvents, ["returnImmediately"] = true };
        if (pendingAck.Count > 0) body["ack"] = new JsonArray(pendingAck.Select(item => (JsonNode)item).ToArray());
        if (pendingErrs.Count > 0)
        {
            var setErrs = new JsonObject();
            foreach (var pair in pendingErrs)
            {
                var one = new JsonObject();
                foreach (var field in pair.Value) one[field.Key] = field.Value;
                setErrs[pair.Key] = one;
            }
            body["setErrs"] = setErrs;
        }
        var (status, raw) = Call("POST", rawUrl, body);
        if (status != 200)
        {
            lock (mu)
            {
                ack.InsertRange(0, pendingAck);
                foreach (var pair in pendingErrs)
                    if (!errs.ContainsKey(pair.Key)) errs[pair.Key] = pair.Value;
            }
            throw new GnapException("ssf", "the poll answered " + status + ": " + Clip(raw, 300));
        }
        JsonObject envelope;
        try { envelope = string.IsNullOrEmpty(raw) ? new JsonObject() : JsonUtil.Obj(JsonUtil.Parse(raw)); }
        catch (Exception err) { throw new GnapException("ssf", "the poll answered 200 with a body that is not JSON", err); }
        if (envelope == null) throw new GnapException("ssf", "the poll answered 200 with a body that is not JSON");
        var sets = envelope["sets"];
        var keysInOrder = new List<string>();
        var tokens = new Dictionary<string, string>();
        if (sets != null && sets is not JsonObject)
            throw new GnapException("ssf", "the poll sets are not a JSON object");
        if (sets is JsonObject setObj)
        {
            foreach (var pair in setObj)
            {
                var token = JsonUtil.Str(pair.Value);
                if (token == null) throw new GnapException("ssf", "the poll sets are not a JSON object");
                keysInOrder.Add(pair.Key);
                tokens[pair.Key] = token;
            }
        }
        foreach (var jti in keysInOrder)
        {
            try { Handle(jti, tokens[jti]); }
            catch (Exception err)
            {
                log.Warn("ssf: SET " + jti + " refused: " + err.Message);
                var code = err is GnapException ge && ge.Code == "signature" ? "invalid_key" : "invalid_request";
                lock (mu) errs[jti] = new Dictionary<string, string> { ["err"] = code, ["description"] = err.Message };
                continue;
            }
            lock (mu) ack.Add(jti);
        }
        return envelope["moreAvailable"] is JsonValue more && more.TryGetValue<bool>(out var flag) && flag;
    }

    void Handle(string jti, string token)
    {
        var published = Jwks(false);
        VerifiedJws verified;
        try { verified = JwsVerify.Compact(token, published); }
        catch (GnapException err) when (SignatureRetry.IsMatch(err.Message))
        {
            published = Jwks(true);
            verified = JwsVerify.Compact(token, published);
        }
        var header = verified.Header;
        var payload = verified.Payload;
        if (header["typ"] != null && (JsonUtil.Str(header["typ"]) ?? "").ToLowerInvariant() != "secevent+jwt")
            throw new GnapException("validation", "the SET's typ is " + (JsonUtil.Str(header["typ"]) ?? header["typ"].ToJsonString()));
        if (JsonUtil.Str(payload["iss"]) != JsonUtil.Str(config["issuer"]))
            throw new GnapException("validation", "the SET was issued by " + (JsonUtil.Str(payload["iss"]) ?? payload["iss"]?.ToJsonString()) + ", not " + JsonUtil.Str(config["issuer"]));
        var want = Audience(Stream["aud"]);
        var got = Audience(payload["aud"]);
        if (want.Count > 0 && !got.Any(want.Contains))
            throw new GnapException("validation", "the SET is for " + string.Join(", ", got) + ", not this stream");
        if (payload["jti"] != null && JsonUtil.Str(payload["jti"]) != jti)
            throw new GnapException("validation", "the SET's jti is not the one it was delivered under");
        var eventMap = JsonUtil.Obj(payload["events"]);
        if (eventMap == null || eventMap.Count == 0) throw new GnapException("validation", "the SET carries no events");
        foreach (var pair in eventMap)
        {
            JsonNode subjectSource = payload["sub_id"];
            if (subjectSource == null) subjectSource = JsonUtil.Obj(pair.Value)?["subject"];
            var subject = Events.SubjectOf(subjectSource, JsonUtil.Str(config["issuer"]));
            var sessions = SessionsFor(pair.Key, subject);
            var ends = endOn.Contains(pair.Key) && sessions.Count > 0;
            var signal = new SignalEvent
            {
                Type = pair.Key,
                Payload = pair.Value,
                Subject = subject,
                Jti = jti,
                Sessions = sessions,
                Ended = ends,
                Txn = payload["txn"] == null ? "" : JsonUtil.Str(payload["txn"]) ?? ""
            };
            if (JsonUtil.TryNumber(payload["iat"], out var iat)) signal.Iat = iat;
            if (ends)
            {
                try { onEnd(sessions, signal); }
                catch (Exception err)
                {
                    log.Error("ssf: onEndSessions threw for " + pair.Key + " (SET " + jti + " is still acknowledged): " + err.Message);
                    signal.Ended = false;
                }
                if (signal.Ended)
                    lock (mu) foreach (var localId in sessions) index.Remove(localId);
            }
            List<Action<SignalEvent>> called;
            lock (mu)
            {
                called = new List<Action<SignalEvent>>();
                if (handlers.TryGetValue(pair.Key, out var typed)) called.AddRange(typed);
                if (handlers.TryGetValue("*", out var star)) called.AddRange(star);
            }
            foreach (var handler in called)
            {
                try { handler(signal); }
                catch (Exception err)
                {
                    log.Error("ssf: a handler for " + pair.Key + " threw (SET " + jti + " is still acknowledged): " + err.Message);
                }
            }
        }
    }

    List<string> SessionsFor(string eventType, Dictionary<string, string> subject)
    {
        if (eventType == Events.Verification || eventType == Events.StreamUpdated) return new List<string>();
        lock (mu)
        {
            if (subject.TryGetValue("idp_session", out var idp) && !string.IsNullOrEmpty(idp))
            {
                var found = index.ByIdp(idp);
                if (found.Count > 0 || eventType == Events.SessionRevoked) return found;
            }
            if (subject.TryGetValue("person", out var person) && !string.IsNullOrEmpty(person)) return index.ByPerson(person);
            if (subject.TryGetValue("email", out var email) && !string.IsNullOrEmpty(email)) return index.ByEmail(email);
            return new List<string>();
        }
    }

    static List<string> Audience(JsonNode value)
    {
        if (value == null) return new List<string>();
        if (JsonUtil.Arr(value) is JsonArray list) return list.Select(item => JsonUtil.Str(item) ?? item.ToJsonString()).ToList();
        if (JsonUtil.Str(value) is string text) return new List<string> { text };
        return new List<string> { value.ToJsonString() };
    }

    static string Clip(string value, int max) => string.IsNullOrEmpty(value) || value.Length <= max ? value ?? "" : value[..max];
}
