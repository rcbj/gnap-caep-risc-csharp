// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Text.Json.Nodes;

namespace IyaSec.Gnap;

public static class Events
{
    public const string Caep = "https://schemas.openid.net/secevent/caep/event-type/";
    public const string Risc = "https://schemas.openid.net/secevent/risc/event-type/";
    public const string Ssf = "https://schemas.openid.net/secevent/ssf/event-type/";

    public const string SessionRevoked = Caep + "session-revoked";
    public const string TokenClaimsChange = Caep + "token-claims-change";
    public const string CredentialChange = Caep + "credential-change";
    public const string AssuranceLevelChange = Caep + "assurance-level-change";
    public const string DeviceComplianceChange = Caep + "device-compliance-change";
    public const string SessionEstablished = Caep + "session-established";
    public const string SessionPresented = Caep + "session-presented";
    public const string RiskLevelChange = Caep + "risk-level-change";
    public const string AccountCredentialChangeRequired = Risc + "account-credential-change-required";
    public const string AccountPurged = Risc + "account-purged";
    public const string AccountDisabled = Risc + "account-disabled";
    public const string AccountEnabled = Risc + "account-enabled";
    public const string IdentifierChanged = Risc + "identifier-changed";
    public const string IdentifierRecycled = Risc + "identifier-recycled";
    public const string CredentialCompromise = Risc + "credential-compromise";
    public const string OptIn = Risc + "opt-in";
    public const string OptOutInitiated = Risc + "opt-out-initiated";
    public const string OptOutCancelled = Risc + "opt-out-cancelled";
    public const string OptOutEffective = Risc + "opt-out-effective";
    public const string RecoveryActivated = Risc + "recovery-activated";
    public const string RecoveryInformationChanged = Risc + "recovery-information-changed";
    public const string SessionsRevoked = Risc + "sessions-revoked";
    public const string Verification = Ssf + "verification";
    public const string StreamUpdated = Ssf + "stream-updated";

    public static readonly string[] DefaultRequested =
    {
        SessionRevoked, CredentialChange, AssuranceLevelChange, TokenClaimsChange,
        AccountDisabled, AccountEnabled, AccountPurged, CredentialCompromise,
        SessionsRevoked, AccountCredentialChangeRequired
    };

    public static readonly string[] DefaultEnding =
    {
        SessionRevoked, AccountDisabled, AccountPurged, CredentialCompromise, SessionsRevoked
    };

    public static Dictionary<string, string> SubjectOf(JsonNode subId, string issuer)
    {
        var doc = JsonUtil.Obj(subId);
        if (doc == null) return new Dictionary<string, string>();
        var format = JsonUtil.Str(doc["format"]);
        if (string.IsNullOrEmpty(format)) format = JsonUtil.Str(doc["subject_type"]);
        if (format == "complex" || (string.IsNullOrEmpty(format) && (doc["user"] != null || doc["session"] != null)))
        {
            var user = Simple(doc["user"], issuer);
            var session = Simple(doc["session"], issuer);
            var outp = new Dictionary<string, string>();
            if (user.TryGetValue("sub", out var person) && person != "") outp["person"] = person;
            if (user.TryGetValue("email", out var email) && email != "") outp["email"] = email;
            var sessionId = session.TryGetValue("opaque", out var opaque) && opaque != "" ? opaque : session.GetValueOrDefault("sub");
            if (!string.IsNullOrEmpty(sessionId)) outp["idp_session"] = sessionId;
            return outp;
        }
        var one = Simple(doc, issuer);
        var flat = new Dictionary<string, string>();
        if (one.TryGetValue("sub", out var sub) && sub != "") flat["person"] = sub;
        if (one.TryGetValue("email", out var mail) && mail != "") flat["email"] = mail;
        return flat;
    }

    static Dictionary<string, string> Simple(JsonNode identifier, string issuer)
    {
        var doc = JsonUtil.Obj(identifier);
        if (doc == null) return new Dictionary<string, string>();
        var format = JsonUtil.Str(doc["format"]);
        if (string.IsNullOrEmpty(format)) format = JsonUtil.Str(doc["subject_type"]);
        var outp = new Dictionary<string, string>();
        switch (format)
        {
            case "iss_sub":
                if (JsonUtil.Str(doc["sub"]) is string sub && (doc["iss"] == null || JsonUtil.Str(doc["iss"]) == issuer))
                    outp["sub"] = sub;
                break;
            case "email":
                if (JsonUtil.Str(doc["email"]) is string email) outp["email"] = email;
                break;
            case "opaque":
                if (JsonUtil.Str(doc["id"]) is string id) outp["opaque"] = id;
                break;
            case "aliases":
                var items = JsonUtil.Arr(doc["identifiers"]);
                if (items != null)
                    foreach (var item in items)
                        foreach (var pair in Simple(item, issuer))
                            outp[pair.Key] = pair.Value;
                break;
        }
        return outp;
    }
}
