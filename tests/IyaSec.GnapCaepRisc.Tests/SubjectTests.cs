// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Text.Json.Nodes;

namespace IyaSec.Gnap.Tests;

public class SubjectTests
{
    static IdCheck Check() => new()
    {
        Issuer = "https://as.example",
        Audiences = Array.Empty<string>(),
        Skew = 0,
        Keys = () => new List<JsonObject>()
    };

    [Fact]
    public void UidFromAccountKeepsTheProtocolSubject()
    {
        var person = Subjects.From(JsonNode.Parse("""
        {"sub_ids":[
          {"format":"iss_sub","iss":"https://as.example","sub":"urn:uuid:abc"},
          {"format":"account","uri":"acct:gnap-demo-user@localhost:8081"}
        ]}
        """), Check());
        Assert.Equal("urn:uuid:abc", person.Sub);
        Assert.Equal("https://as.example", person.Iss);
        Assert.True(person.HasUid);
        Assert.Equal("gnap-demo-user", person.Uid);
    }

    [Fact]
    public void PercentDecodesTheUserPartAndKeepsInvalidEncoding()
    {
        var decoded = Subjects.From(JsonNode.Parse("""
        {"sub_ids":[{"format":"account","uri":"acct:ada%20lovelace@idp.example"}]}
        """), Check());
        Assert.Equal("acct:ada%20lovelace@idp.example", decoded.Sub);
        Assert.True(decoded.HasUid);
        Assert.Equal("ada lovelace", decoded.Uid);
        var kept = Subjects.From(JsonNode.Parse("""
        {"sub_ids":[{"format":"account","uri":"acct:%E0%A4%A@idp.example"}]}
        """), Check());
        Assert.True(kept.HasUid);
        Assert.Equal("%E0%A4%A", kept.Uid);
    }

    [Fact]
    public void UidStaysUnsetWithoutAnAccountIdentifier()
    {
        var person = Subjects.From(JsonNode.Parse("""
        {"sub_ids":[{"format":"iss_sub","iss":"https://as.example","sub":"urn:uuid:abc"}]}
        """), Check());
        Assert.False(person.HasUid);
        Assert.Null(person.Uid);
        Assert.Equal("urn:uuid:abc", person.Sub);
    }
}
