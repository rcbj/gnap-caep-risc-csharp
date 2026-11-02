// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

namespace IyaSec.Gnap;

public sealed class TrackedSession
{
    public string LocalId { get; init; }
    public string Person { get; init; }
    public string Email { get; init; }
    public string IdpSession { get; init; }
    public double? ExpiresAt { get; init; }
}

public static class Sessions
{
    public static TrackedSession FromPerson(string localId, Person person, double? expiresAt)
    {
        return new TrackedSession
        {
            LocalId = localId,
            ExpiresAt = expiresAt,
            Person = person?.Sub,
            Email = person?.Email,
            IdpSession = person?.Sid
        };
    }
}

sealed class MemoryIndex
{
    readonly Dictionary<string, TrackedSession> sessions = new();
    readonly List<string> order = new();
    const int Max = 100000;

    public void Add(TrackedSession session)
    {
        if (!sessions.ContainsKey(session.LocalId) && sessions.Count >= Max)
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            foreach (var key in sessions.Where(p => p.Value.ExpiresAt != null && p.Value.ExpiresAt <= now).Select(p => p.Key).ToList())
                Remove(key);
            while (sessions.Count >= Max && order.Count > 0) Remove(order[0]);
        }
        var stored = session;
        if (!string.IsNullOrEmpty(session.Email))
            stored = new TrackedSession
            {
                LocalId = session.LocalId, Person = session.Person, Email = session.Email.ToLowerInvariant(),
                IdpSession = session.IdpSession, ExpiresAt = session.ExpiresAt
            };
        if (!sessions.ContainsKey(stored.LocalId)) order.Add(stored.LocalId);
        sessions[stored.LocalId] = stored;
    }

    public void Remove(string localId)
    {
        if (!sessions.Remove(localId)) return;
        order.RemoveAll(id => id == localId);
    }

    public List<string> ByPerson(string person) => Find(session => session.Person == person);

    public List<string> ByEmail(string email)
    {
        var wanted = (email ?? "").ToLowerInvariant();
        return Find(session => session.Email == wanted);
    }

    public List<string> ByIdp(string idp) => Find(session => session.IdpSession == idp);

    List<string> Find(Func<TrackedSession, bool> match)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var outp = new List<string>();
        foreach (var id in order.ToList())
        {
            if (!sessions.TryGetValue(id, out var value)) continue;
            if (value.ExpiresAt != null && value.ExpiresAt <= now)
            {
                Remove(id);
                continue;
            }
            if (match(value)) outp.Add(id);
        }
        return outp;
    }
}
