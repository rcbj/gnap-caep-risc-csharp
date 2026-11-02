// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace IyaSec.Gnap;

static class JsonUtil
{
    public static readonly JsonSerializerOptions DumpOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public static string Dump(JsonNode node) => node.ToJsonString(DumpOptions);

    public static JsonNode Parse(string text)
    {
        var node = JsonNode.Parse(text);
        if (node == null) throw new JsonException("empty");
        return node;
    }

    public static string B64Url(byte[] data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] B64UrlDecode(string value)
    {
        var text = value.Replace('-', '+').Replace('_', '/');
        switch (text.Length % 4)
        {
            case 2: text += "=="; break;
            case 3: text += "="; break;
        }
        return Convert.FromBase64String(text);
    }

    public static string B64Std(byte[] data) => Convert.ToBase64String(data);

    public static byte[] Sha256(byte[] data) => SHA256.HashData(data);

    public static bool TimingEqual(string a, string b)
    {
        var left = Encoding.UTF8.GetBytes(a ?? "");
        var right = Encoding.UTF8.GetBytes(b ?? "");
        return CryptographicOperations.FixedTimeEquals(left, right);
    }

    public static bool TryNumber(JsonNode node, out double number)
    {
        number = 0;
        if (node is not JsonValue value) return false;
        if (value.TryGetValue<bool>(out _)) return false;
        if (value.TryGetValue<double>(out number)) return true;
        if (value.TryGetValue<long>(out var whole))
        {
            number = whole;
            return true;
        }
        if (value.TryGetValue<int>(out var integer))
        {
            number = integer;
            return true;
        }
        return false;
    }

    public static JsonObject Obj(JsonNode node) => node as JsonObject;

    public static JsonArray Arr(JsonNode node) => node as JsonArray;

    public static string Str(JsonNode node)
    {
        if (node is JsonValue value && value.TryGetValue<string>(out var text)) return text;
        return null;
    }
}
