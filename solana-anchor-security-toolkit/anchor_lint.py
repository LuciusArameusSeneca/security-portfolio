#!/usr/bin/env python3
"""
anchor_lint.py - Heuristischer Sicherheits-Linter fuer Solana-Anchor-Programme.

Durchsucht .rs-Dateien nach 6 haeufigen, real vorkommenden Solana/Anchor-
Schwachstellenklassen:

  1. unchecked-arithmetic   Ungeprüfte +/-/* auf Zahlenwerten (Overflow/Underflow)
  2. missing-signer         Konto heisst wie eine Autoritaet, ist aber kein Signer<'info>
  3. unconstrained-account  Rohe AccountInfo/UncheckedAccount ganz ohne #[account(...)]
  4. missing-seeds          Datenkonto ohne seeds/bump-Constraint (PDA nicht validiert)
  5. missing-has-one        Datenkonto neben einem Signer, aber ohne has_one/constraint
  6. manual-close           Manuelles Lamports-auf-0-Setzen statt `close = <account>`
  7. raw-token-program      token_program als rohe AccountInfo statt Program<'info, Token>

WICHTIG - Grenzen dieses Tools (bewusst kein Marketing-Ueberversprechen):
Dies ist ein einfacher, regex-/heuristik-basierter Textscanner - KEIN
vollstaendiger Rust-/Anchor-Parser und KEIN Ersatz fuer ein manuelles Audit
oder einen Compiler. Er kann sowohl False Positives (harmlose, aber
ungewoehnlich geschriebene Stellen) als auch False Negatives (Bugs in
Formulierungen, die die Heuristiken nicht erkennen) produzieren. Nutze ihn
als schnellen ERSTEN Filter/Checkliste, nicht als abschliessendes Ergebnis.

Nutzung:
    python3 anchor_lint.py pfad/zur/datei.rs
    python3 anchor_lint.py pfad/zum/programs-ordner/          (rekursiv, *.rs)
    python3 anchor_lint.py --json pfad/                       (maschinenlesbar)

Exit-Code: 1 falls mindestens ein HIGH-Fund vorliegt, sonst 0 (auch bei
MEDIUM/INFO-Funden) - so laesst sich das Tool in CI als "harter Blocker" nur
fuer die schwerwiegendsten Faelle einsetzen, waehrend MEDIUM/INFO als
Hinweise fuer die manuelle Review sichtbar bleiben.
"""
import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Optional

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}


@dataclass
class Finding:
    file: str
    line: int
    severity: str
    check: str
    message: str
    snippet: str

    def format(self) -> str:
        return (
            f"[{self.severity}] {self.file}:{self.line} ({self.check})\n"
            f"    {self.snippet.strip()}\n"
            f"    -> {self.message}"
        )


# ---------------------------------------------------------------------------
# Hilfsfunktionen: robustes Extrahieren von #[...]-Attributen und Feldern aus
# einem Accounts-Struct-Body. Eine einfache Zeichenklassen-Regex wie
# r'#\[[^\]]*\]' wuerde bei VERSCHACHTELTEN eckigen Klammern zu frueh
# abbrechen (z.B. bei `seeds = [b"vault", owner.key().as_ref()]` innerhalb
# eines #[account(...)]-Attributs) - deshalb zaehlen wir die Klammertiefe
# manuell mit.
# ---------------------------------------------------------------------------

def _find_bracketed_attrs(text: str) -> List[Dict]:
    attrs = []
    i, n = 0, len(text)
    while i < n:
        if text[i] == '#' and i + 1 < n and text[i + 1] == '[':
            depth = 0
            j = i + 1
            start = i
            while j < n:
                if text[j] == '[':
                    depth += 1
                elif text[j] == ']':
                    depth -= 1
                    if depth == 0:
                        j += 1
                        break
                j += 1
            attrs.append({"start": start, "end": j, "text": text[start:j]})
            i = j
        else:
            i += 1
    return attrs


_FIELD_START_RE = re.compile(r'pub\s+(\w+)\s*:\s*')


def _extract_fields(body: str) -> List[tuple]:
    """Findet Feldname+Typ per Klammertiefe (statt einer Komma-Zeichenklasse),
    damit generische Typen mit Komma wie Account<'info, Vault> nicht schon am
    inneren Komma abgeschnitten werden."""
    fields = []
    n = len(body)
    for m in _FIELD_START_RE.finditer(body):
        name = m.group(1)
        start = m.start()
        i = m.end()
        depth = 0
        while i < n:
            c = body[i]
            if c in "<(":
                depth += 1
            elif c in ">)":
                depth -= 1
            elif c == "," and depth <= 0:
                break
            i += 1
        ftype = body[m.end():i].strip()
        fields.append((start, name, ftype))
    return fields


_STRUCT_RE = re.compile(
    r'#\[derive\(Accounts\)\]\s*(?:#\[[^\]]*\]\s*)*pub\s+struct\s+(\w+)\s*(?:<[^>]*>)?\s*\{',
)


def _extract_accounts_structs(text: str) -> List[Dict]:
    """Findet jeden #[derive(Accounts)]-Struct-Body (per Klammertiefe, damit
    verschachtelte generische Typen wie Account<'info, Vault> nicht
    verwirren) und parst dessen Felder inkl. der direkt darueberstehenden
    #[account(...)]-Attribute."""
    structs = []
    for m in _STRUCT_RE.finditer(text):
        name = m.group(1)
        body_start = m.end()
        depth = 1
        i = body_start
        while i < len(text) and depth > 0:
            if text[i] == '{':
                depth += 1
            elif text[i] == '}':
                depth -= 1
            i += 1
        body = text[body_start:i - 1]
        body_offset = body_start

        attrs = _find_bracketed_attrs(body)
        fields = _extract_fields(body)

        parsed_fields = []
        prev_end = 0
        for field_start, fname, ftype in fields:
            field_attrs = [a["text"] for a in attrs if prev_end <= a["start"] < field_start]
            line_no = text[:body_offset + field_start].count("\n") + 1
            parsed_fields.append({
                "name": fname, "type": ftype, "attrs": field_attrs, "line": line_no,
            })
            prev_end = field_start

        structs.append({"name": name, "fields": parsed_fields})
    return structs


# ---------------------------------------------------------------------------
# Check 1: ungeprüfte Arithmetik (Overflow/Underflow)
# ---------------------------------------------------------------------------

_CHECKED_HINT_RE = re.compile(r'checked_|saturating_|wrapping_')
_COMPOUND_ASSIGN_RE = re.compile(r'^\s*\**[\w\.\(\)]+\s*(\+=|-=|\*=)\s*.+;', re.MULTILINE)
_SELF_ARITH_RE = re.compile(
    r'^\s*(?P<lhs>\**[\w]+(?:\.\w+)*)\s*=\s*(?P<rhs>.+);\s*$', re.MULTILINE
)


def check_unchecked_arithmetic(text: str, filename: str) -> List[Finding]:
    findings = []
    lines = text.splitlines()

    for m in _COMPOUND_ASSIGN_RE.finditer(text):
        line_no = text[:m.start()].count("\n") + 1
        line_text = lines[line_no - 1]
        findings.append(Finding(
            file=filename, line=line_no, severity="HIGH",
            check="unchecked-arithmetic",
            message=(
                "Compound-Zuweisung (+=/-=/*=) auf einem Zahlenwert - kann in Rust "
                "im Release-Build (Solana-Programme werden i.d.R. mit "
                "overflow-checks=false gebaut) still ueber-/unterlaufen. Durch "
                "checked_add()/checked_sub()/checked_mul() + ok_or(FehlerCode)? ersetzen."
            ),
            snippet=line_text,
        ))

    for m in _SELF_ARITH_RE.finditer(text):
        lhs, rhs = m.group("lhs"), m.group("rhs")
        if _CHECKED_HINT_RE.search(rhs):
            continue
        if not re.search(r'[+\-*]', rhs):
            continue
        lhs_bare = lhs.lstrip("*")
        if lhs_bare not in rhs:
            continue
        line_no = text[:m.start()].count("\n") + 1
        line_text = lines[line_no - 1]
        findings.append(Finding(
            file=filename, line=line_no, severity="HIGH",
            check="unchecked-arithmetic",
            message=(
                f"Selbstbezuegliche Zuweisung '{lhs_bare} = {lhs_bare} <op> ...' ohne "
                "checked_add/checked_sub/checked_mul - klassisches Muster fuer einen "
                "unbemerkten Integer-Overflow/-Underflow (z.B. Balance-Manipulation)."
            ),
            snippet=line_text,
        ))
    return findings


# ---------------------------------------------------------------------------
# Check 2-5 + 7: Accounts-Struct-Feldpruefungen
# ---------------------------------------------------------------------------

_AUTHORITY_NAME_RE = re.compile(r'(authority|owner|admin)$', re.IGNORECASE)
_SENSITIVE_DATA_NAME_RE = re.compile(r'(vault|pda|state|pool|escrow|treasury)', re.IGNORECASE)


def check_accounts_structs(text: str, filename: str) -> List[Finding]:
    findings = []
    structs = _extract_accounts_structs(text)

    for struct in structs:
        fields = struct["fields"]
        has_signer_authority = any(
            "Signer<" in f["type"] and _AUTHORITY_NAME_RE.search(f["name"])
            for f in fields
        )

        for f in fields:
            name, ftype, attrs, line = f["name"], f["type"], f["attrs"], f["line"]
            attrs_text = " ".join(attrs)
            is_raw_account = "AccountInfo" in ftype or "UncheckedAccount" in ftype
            is_data_account = ftype.strip().startswith("Account<")

            # Check 2: missing-signer
            if is_raw_account and _AUTHORITY_NAME_RE.search(name) and "Signer<" not in ftype:
                findings.append(Finding(
                    file=filename, line=line, severity="HIGH", check="missing-signer",
                    message=(
                        f"Feld '{name}' klingt nach einer Autoritaet/einem Owner, ist aber "
                        f"'{ftype}' statt 'Signer<\\'info>' - Anchor erzwingt hier KEINE "
                        "Transaktionssignatur. Pruefe, ob dieses Konto tatsaechlich als "
                        "Signer<'info> deklariert werden muss."
                    ),
                    snippet=f"pub {name}: {ftype},",
                ))

            # Check 3: unconstrained-account
            if is_raw_account and not attrs:
                findings.append(Finding(
                    file=filename, line=line, severity="INFO", check="unconstrained-account",
                    message=(
                        f"Feld '{name}' ({ftype}) hat KEIN #[account(...)]-Attribut - keine "
                        "erkennbare Einschraenkung (weder mut, seeds, has_one noch constraint). "
                        "Manuell pruefen, ob hier signer-/owner-/seeds-Validierung noetig waere."
                    ),
                    snippet=f"pub {name}: {ftype},",
                ))

            # Check 4: missing-seeds (nur fuer Daten-Accounts mit "sensiblem" Namen)
            if is_data_account and _SENSITIVE_DATA_NAME_RE.search(name) and "seeds" not in attrs_text:
                findings.append(Finding(
                    file=filename, line=line, severity="MEDIUM", check="missing-seeds",
                    message=(
                        f"Feld '{name}' ({ftype}) hat kein 'seeds'/'bump'-Constraint. Falls "
                        "die Adresse dieses Kontos deterministisch aus Programm-Logik "
                        "hergeleitet werden sollte (typisch fuer Vault/Pool/State-PDAs), "
                        "fehlt hier die Validierung - ein Aufrufer koennte sonst ein "
                        "beliebiges Konto desselben Typs einreichen."
                    ),
                    snippet=f"pub {name}: {ftype},",
                ))

            # Check 5: missing-has-one (nicht bei `init` - das Konto wird hier
            # erst neu angelegt, has_one koennte gegen einen noch gar nicht
            # existierenden alten Wert pruefen und ist an dieser Stelle
            # semantisch nicht anwendbar).
            if (is_data_account and has_signer_authority and "init" not in attrs_text
                    and "has_one" not in attrs_text and "constraint" not in attrs_text):
                findings.append(Finding(
                    file=filename, line=line, severity="MEDIUM", check="missing-has-one",
                    message=(
                        f"Feld '{name}' ({ftype}) steht neben einem Signer mit "
                        "Autoritaets-Namen, hat aber weder 'has_one' noch 'constraint' - "
                        "pruefe, ob Anchor hier automatisch verifizieren sollte, dass dieses "
                        "Konto tatsaechlich zum aufrufenden Signer gehoert."
                    ),
                    snippet=f"pub {name}: {ftype},",
                ))

            # Check 7: raw-token-program
            if is_raw_account and re.search(r'token_program', name, re.IGNORECASE):
                findings.append(Finding(
                    file=filename, line=line, severity="MEDIUM", check="raw-token-program",
                    message=(
                        f"Feld '{name}' ist '{ftype}' statt 'Program<\\'info, Token>' - "
                        "Anchor validiert die Programm-ID nur beim typisierten "
                        "Program<'info, T>. Eine rohe AccountInfo laesst einen Aufrufer "
                        "JEDES beliebige Programm als 'Token-Programm' einreichen."
                    ),
                    snippet=f"pub {name}: {ftype},",
                ))
    return findings


# ---------------------------------------------------------------------------
# Check 6: manuelles Schliessen statt `close = <account>`
# ---------------------------------------------------------------------------

_MANUAL_ZERO_RE = re.compile(r'\.lamports\.borrow_mut\(\)\s*=\s*0\s*;')
_CLOSE_CONSTRAINT_RE = re.compile(r'\bclose\s*=\s*\w+')


def check_manual_close(text: str, filename: str) -> List[Finding]:
    if _CLOSE_CONSTRAINT_RE.search(text):
        return []
    findings = []
    lines = text.splitlines()
    for m in _MANUAL_ZERO_RE.finditer(text):
        line_no = text[:m.start()].count("\n") + 1
        findings.append(Finding(
            file=filename, line=line_no, severity="MEDIUM", check="manual-close",
            message=(
                "Manuelles Nullsetzen der Lamports gefunden, aber keine 'close = <konto>' "
                "-Constraint irgendwo in der Datei. Anchors close-Constraint setzt "
                "zusaetzlich die Kontodaten/Discriminator zurueck und verhindert damit "
                "'Revival'-Angriffe (das geschlossene Konto als noch 'lebendig' lesen), "
                "was reines Lamports-auf-0-Setzen allein nicht tut."
            ),
            snippet=lines[line_no - 1],
        ))
    return findings


def lint_text(text: str, filename: str) -> List[Finding]:
    findings = []
    findings += check_unchecked_arithmetic(text, filename)
    findings += check_accounts_structs(text, filename)
    findings += check_manual_close(text, filename)
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.line))
    return findings


def lint_file(path: Path) -> List[Finding]:
    text = path.read_text(encoding="utf-8", errors="replace")
    return lint_text(text, str(path))


def lint_path(path: Path) -> List[Finding]:
    if path.is_file():
        return lint_file(path)
    findings = []
    for rs_file in sorted(path.rglob("*.rs")):
        findings += lint_file(rs_file)
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Heuristischer Sicherheits-Linter fuer Solana-Anchor-Programme.")
    parser.add_argument("path", help="Pfad zu einer .rs-Datei oder einem Ordner (rekursiv durchsucht)")
    parser.add_argument("--json", action="store_true", help="Ausgabe als JSON statt Klartext")
    args = parser.parse_args()

    target = Path(args.path)
    if not target.exists():
        print(f"Pfad nicht gefunden: {target}", file=sys.stderr)
        return 2

    findings = lint_path(target)

    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2, ensure_ascii=False))
    else:
        if not findings:
            print("Keine Funde. (Denk daran: heuristischer Linter, ersetzt kein manuelles Audit.)")
        for f in findings:
            print(f.format())
            print()
        counts = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        print(f"Zusammenfassung: {counts}")

    return 1 if any(f.severity == "HIGH" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
