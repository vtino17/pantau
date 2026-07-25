import argparse
import json
import sys

from . import __version__
from .checker import check
from .patterns import INDO_SCAM_KEYWORDS


RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def color_level(level: str) -> str:
    if level == "bahaya":
        return f"{RED}{BOLD}BAHAYA{RESET}"
    if level == "mencurigakan":
        return f"{YELLOW}{BOLD}MENCURIGAKAN{RESET}"
    if level == "ringan":
        return f"{YELLOW}RINGAN{RESET}"
    return f"{GREEN}AMAN{RESET}"


def print_check(result: dict, verbose: bool = False, json_output: bool = False, quiet: bool = False):
    h = result["heuristics"]

    if json_output:
        output = {
            "url": result["original"],
            "domain": result["domain"],
            "expanded": result.get("expanded"),
            "hops": result.get("hops", []),
            "score": h["score"],
            "level": h["level"],
            "findings": h["findings"]
        }
        print(json.dumps(output, indent=2, ensure_ascii=False))
        return

    if quiet:
        print(h["score"])
        return

    print(f"\n{BOLD}Pantau — Hasil Inspeksi{RESET}")
    print(f"{DIM}{'='*40}{RESET}")
    print(f"{BOLD}URL:{RESET}       {result['original']}")
    print(f"{BOLD}Domain:{RESET}    {result['domain']}")

    if result.get("expanded"):
        print(f"{BOLD}Asli:{RESET}     {result['expanded']}")
        if verbose and len(result.get("hops", [])) > 1:
            print(f"{BOLD}Rantai:{RESET}")
            for i, hop in enumerate(result["hops"]):
                prefix = "  └─" if i == len(result["hops"]) - 1 else "  ├─"
                print(f"{DIM}{prefix} {hop}{RESET}")

    print(f"\n{BOLD}Skor Risiko:{RESET} {h['score']}/100")
    print(f"{BOLD}Tingkat:{RESET}    {color_level(h['level'])}")

    if h["findings"]:
        print(f"\n{BOLD}Temuan:{RESET}")
        for f in h["findings"]:
            severity = RED if any(w in f for w in ["fising", "IP", "@", "bersarang", "mirip", "Bangking", "Paket", "Instansi", "Fintech", "TLD"]) else YELLOW
            print(f"  {severity}⚠{RESET} {f}")

    if h["level"] == "aman" and not h["findings"]:
        print(f"\n{GREEN}✓ Tidak ditemukan pola mencurigakan.{RESET}")


def print_patterns():
    print(f"\n{BOLD}Pola Penipuan yang Terdeteksi:{RESET}")
    print(f"{DIM}{'='*40}{RESET}")
    for category, info in INDO_SCAM_KEYWORDS.items():
        emoji = "🔴" if info["risk"] == "high" else "🟡"
        words = ", ".join(info["words"])
        print(f"\n{emoji} {BOLD}{info['label']}{RESET}")
        print(f"   Kata kunci: {DIM}{words}{RESET}")
    print()


def main():
    parser = argparse.ArgumentParser(
        prog="pantau",
        description="Pantau — CLI inspeksi keamanan link & domain",
    )
    parser.add_argument("-V", "--version", action="version", version=f"pantau {__version__}")

    sub = parser.add_subparsers(dest="command")

    check_p = sub.add_parser("check", help="Periksa URL/domain")
    check_p.add_argument("url", help="URL atau domain yang akan diperiksa")
    check_p.add_argument("-v", "--verbose", action="store_true", help="Tampilkan detail lengkap")
    check_p.add_argument("--json", action="store_true", help="Output dalam format JSON")
    check_p.add_argument("-q", "--quiet", action="store_true", help="Hanya tampilkan skor risiko")

    sub.add_parser("patterns", help="Daftar pola penipuan yang dikenali")

    args = parser.parse_args()

    if args.command == "check":
        result = check(args.url)
        print_check(result, verbose=args.verbose, json_output=args.json, quiet=args.quiet)
    elif args.command == "patterns":
        print_patterns()
    else:
        parser.print_help()
        sys.exit(1)