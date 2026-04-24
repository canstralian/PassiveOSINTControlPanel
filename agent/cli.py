"""Command-line interface for the OSINT Expert Agent."""

from __future__ import annotations

import argparse

from .osint_agent import OSINTAgent


def interactive_mode(agent: OSINTAgent) -> None:
    print("OSINT Expert Agent — Interactive Mode")
    print("Commands: 'exit'/'quit' to end, 'reset' to clear history.\n")
    while True:
        try:
            user_input = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break
        if not user_input:
            continue
        if user_input.lower() in ("exit", "quit"):
            print("Session ended.")
            break
        if user_input.lower() == "reset":
            agent.reset()
            print("[Conversation history cleared]\n")
            continue
        print("Agent: ", end="", flush=True)
        for chunk in agent.stream_chat(user_input):
            print(chunk, end="", flush=True)
        print("\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="OSINT Expert Agent powered by Claude claude-opus-4-7",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m agent.cli                               # interactive mode
  python -m agent.cli --target example.com          # full analysis
  python -m agent.cli --target example.com --type passive
  python -m agent.cli --target 1.2.3.4 --type threat --context "seen in phishing"
  python -m agent.cli --iocs 1.2.3.4 bad.com abc123hash
  python -m agent.cli --explain "certificate transparency log mining"
        """,
    )
    parser.add_argument("--target", "-t", help="Target to analyze (domain, IP, username, etc.)")
    parser.add_argument(
        "--type",
        choices=["full", "passive", "threat", "footprint", "breach", "darkweb", "socmint"],
        default="full",
        help="Analysis type (default: full)",
    )
    parser.add_argument("--context", "-c", help="Additional context for the analysis")
    parser.add_argument("--iocs", nargs="+", metavar="IOC", help="IOCs for enrichment report")
    parser.add_argument("--explain", "-e", metavar="TECHNIQUE", help="Explain an OSINT technique")
    parser.add_argument("--model", default="claude-opus-4-7", help="Claude model to use")
    parser.add_argument("--no-stream", action="store_true", help="Disable streaming output")

    args = parser.parse_args()
    agent = OSINTAgent(model=args.model)

    if args.iocs:
        result = agent.generate_ioc_report(args.iocs)
        print(result)
    elif args.explain:
        result = agent.explain_technique(args.explain)
        print(result)
    elif args.target:
        prompt = OSINTAgent._build_analysis_prompt(args.target, args.type, args.context)
        if args.no_stream:
            result = agent.chat(prompt)
            print(result)
        else:
            for chunk in agent.stream_chat(prompt):
                print(chunk, end="", flush=True)
            print()
    else:
        interactive_mode(agent)


if __name__ == "__main__":
    main()
