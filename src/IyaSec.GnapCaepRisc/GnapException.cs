// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

namespace IyaSec.Gnap;

/// <summary>A config, discovery, protocol, validation, signature, or ssf failure.</summary>
public sealed class GnapException : Exception
{
    public string Code { get; }
    public string GnapError { get; }
    public object Context { get; set; }
    public Continuation Continuation { get; }

    public GnapException(string code, string message, Exception cause = null, string gnapError = null, object context = null, Continuation continuation = null)
        : base(message, cause)
    {
        Code = code;
        GnapError = gnapError;
        Context = context;
        Continuation = continuation;
    }
}
