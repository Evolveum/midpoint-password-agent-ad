// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.
// Project-level suppressions either have no target or are given
// a specific target and scoped to a namespace, type, member, etc.

using System.Diagnostics.CodeAnalysis;

[assembly: SuppressMessage("StyleCop.CSharp.SpacingRules", "SA1010:Opening square brackets should be spaced correctly", Justification = "Breaks formatting", Scope = "member", Target = "~M:Crypto.WindowsKeyProvider.GetAllKeyVersions~System.Collections.Generic.IEnumerable{System.String}")]
[assembly: SuppressMessage("Style", "IDE0305:Simplify collection initialization", Justification = "Decreases readability", Scope = "member", Target = "~M:Crypto.WindowsKeyProvider.GetAllKeyVersions~System.Collections.Generic.IEnumerable{System.String}")]
[assembly: SuppressMessage("Minor Code Smell", "S6608:Prefer indexing instead of \"Enumerable\" methods on types implementing \"IList\"", Justification = "Decreases readability", Scope = "member", Target = "~M:Crypto.CryptoService.ExtractKeyVersion(System.String)~System.String")]
