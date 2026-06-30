using System;
using CommandLine;

namespace MockServer;

public enum ResponseStrategy
{
    // server return 200 for each request
    SuccessEach,

    // server return 200 for request with valid body, otherwise 400
    SuccessValid,

    // server return error 400 for each request
    ErrorEach,

    // server return 200 only for each nth request
    SuccessNth
}
public class CommandLineOptions
{

    [Option('p', "port", Required = false, HelpText = "Set port on which wire mock server is running")]
    public int Port { get; set; } = 8080;

    [Option('s', "strategy", Required = false, HelpText = "Which strategy to use (default SuccessValid)")]
    public ResponseStrategy Strategy { get; set; } = ResponseStrategy.SuccessValid;

    [Option('n', "nth success", Required = false, HelpText = "When using strategy SuccessNth, which request returns success (default 3)")]
    public int NthSuccess { get; set; } = 3;
};