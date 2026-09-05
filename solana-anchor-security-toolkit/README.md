# Solana / Anchor Smart Contract Security Guide + Linter

Ein praktischer, code-basierter Leitfaden zu 5 häufig real vorkommenden
Solana/Anchor-Schwachstellenklassen - inklusive verwundbarem Beispiel-Contract,
korrigierter Version desselben Contracts und einem selbst geschriebenen,
funktionierenden Analyse-Tool (`anchor_lint.py`), das genau diese Klassen
automatisiert erkennt.

Kein Framework, keine externen Abhängigkeiten nötig - alles hier ist
eigenständig lauffähig mit Python 3 (Standardbibliothek) bzw. `anchor_lang`
(Rust) als Referenz.

## Inhalt dieses Ordners

| Datei | Zweck |
|---|---|
| [`examples/vulnerable_program.rs`](examples/vulnerable_program.rs) | Bewusst unsicherer Beispiel-Vault-Contract mit 5 markierten Schwachstellen |
| [`examples/fixed_program.rs`](examples/fixed_program.rs) | Derselbe Contract, alle 5 Schwachstellen behoben |
| [`anchor_lint.py`](anchor_lint.py) | Heuristischer Python-Linter, der genau diese Schwachstellenklassen in beliebigem Anchor-Rust-Code erkennt |
| [`test_anchor_lint.py`](test_anchor_lint.py) | Automatisierter Beweis, dass der Linter die unsichere Datei erkennt und die korrigierte Datei sauber durchwinkt |

## Schnellstart

```bash
# Eigenen Anchor-Code (oder einen ganzen programs/-Ordner) prüfen:
python3 anchor_lint.py pfad/zu/deinem/programm.rs
python3 anchor_lint.py pfad/zum/programs-ordner/          # rekursiv, *.rs

# Maschinenlesbare Ausgabe (z.B. für CI):
python3 anchor_lint.py --json pfad/ > findings.json

# Das Tool an den beiden Referenzbeispielen ausprobieren:
python3 anchor_lint.py examples/vulnerable_program.rs   # -> mehrere HIGH-Funde, Exit-Code 1
python3 anchor_lint.py examples/fixed_program.rs        # -> keine Funde, Exit-Code 0

# Selbsttest ausführen:
python3 -m unittest test_anchor_lint.py -v
```

**Wichtig - ehrliche Einordnung:** `anchor_lint.py` ist ein einfacher,
regex-/heuristik-basierter Textscanner, **kein** vollständiger Rust-Parser
und **kein** Ersatz für ein manuelles Audit oder einen Compiler-Check. Er
kann sowohl False Positives als auch False Negatives produzieren. Er ist
als schneller erster Filter/Checkliste gedacht, nicht als abschließendes
Ergebnis - das gilt genauso für jeden anderen Report in diesem Repository.

---

## Die 5 Schwachstellenklassen

### 1. Ungeprüfte Arithmetik (Integer-Overflow/-Underflow)

Solana-Programme werden in der Regel **ohne** Rusts `overflow-checks` im
Release-Modus gebaut. Ein simples `balance + amount` oder `balance - amount`
läuft bei einem Über-/Unterlauf still über den `u64`-Wertebereich, statt mit
einem Panic abzubrechen.

```rust
// VERWUNDBAR
vault.balance = vault.balance - amount;   // amount > balance? -> Wrap-Around zu einer riesigen Zahl
```

```rust
// KORRIGIERT
vault.balance = vault.balance
    .checked_sub(amount)
    .ok_or(VaultError::InsufficientFunds)?;   // schlägt sauber fehl statt zu unterlaufen
```

`checked_add` / `checked_sub` / `checked_mul` geben `Option<T>` zurück -
`None` bei einem Über-/Unterlauf. Kombiniert mit `.ok_or(FehlerCode)?` wird
daraus ein regulärer, für den Client sichtbarer Transaktionsfehler statt
stiller Datenkorruption.

### 2. Fehlende PDA-Validierung (`seeds`/`bump`)

Ein Konto, dessen Adresse eigentlich deterministisch aus Programm-Logik
abgeleitet sein sollte (typisch für Vault-/Pool-/State-Accounts), aber ohne
`seeds`/`bump`-Constraint deklariert ist, wird von Anchor nur auf den
richtigen **Typ** geprüft - nicht auf die richtige **Adresse**. Ein Aufrufer
kann dann ein beliebiges, selbst kontrolliertes Konto desselben Typs
einreichen.

```rust
// VERWUNDBAR - jedes Account<'info, Vault>-Konto wird akzeptiert
#[account(mut)]
pub vault: Account<'info, Vault>,
```

```rust
// KORRIGIERT - nur genau DIESE eine PDA wird akzeptiert
#[account(
    mut,
    seeds = [b"vault", owner.key().as_ref()],
    bump = vault.bump,
)]
pub vault: Account<'info, Vault>,
```

### 3. Fehlende Signer-Prüfung

Wenn ein Konto, das eine Autorisierung darstellen soll (z.B. `authority`,
`owner`, `admin`), als rohe `AccountInfo<'info>` statt als `Signer<'info>`
deklariert ist, erzwingt Anchor **keine** Transaktionssignatur für dieses
Konto. Ein Angreifer kann den Public Key des echten Owners einfach als
Kontodaten mitschicken, ohne dessen privaten Schlüssel zu besitzen.

```rust
// VERWUNDBAR - keine Signatur erforderlich
pub authority: AccountInfo<'info>,
```

```rust
// KORRIGIERT
pub owner: Signer<'info>,
```

### 4. Fehlende Ownership-Verknüpfung (`has_one`)

Selbst mit einem echten `Signer<'info>` bleibt eine Lücke, wenn nirgends
geprüft wird, dass genau **dieser** Signer auch zu genau **diesem** Datenkonto
gehört. `has_one` lässt Anchor das automatisch verifizieren.

```rust
// KORRIGIERT - Anchor prüft automatisch: vault.owner == owner.key()
#[account(
    mut,
    seeds = [b"vault", owner.key().as_ref()],
    bump = vault.bump,
    has_one = owner,
)]
pub vault: Account<'info, Vault>,
pub owner: Signer<'info>,
```

### 5. Manuelles Schließen statt `close = <konto>`

Ein Konto von Hand zu "schließen", indem man nur die Lamports auf 0 setzt,
lässt die Kontodaten (inkl. Discriminator) unverändert im Ledger stehen.
Anchors `close`-Constraint setzt zusätzlich die Daten zurück und weist das
Konto dem System-Programm zu - das verhindert sogenannte "Revival"-Angriffe,
bei denen ein eigentlich geschlossenes Konto noch als "lebendig" gelesen
oder in einer späteren Instruktion derselben Transaktion wiederverwendet
werden kann.

```rust
// VERWUNDBAR - Daten/Discriminator bleiben stehen
**vault_ai.lamports.borrow_mut() = 0;
```

```rust
// KORRIGIERT - deklarativ, Anchor übernimmt Daten-Reset + Zuweisung
#[account(mut, close = destination, /* ... */)]
pub vault: Account<'info, Vault>,
```

---

## Warum dieses Tool, nicht nur ein Blogpost?

Die meisten Security-Guides bleiben reiner Fließtext. Dieser hier kommt mit
einem Werkzeug, das man sofort gegen den eigenen Code laufen lassen kann -
und das per Selbsttest ([`test_anchor_lint.py`](test_anchor_lint.py))
nachweislich zwischen der unsicheren und der korrigierten Referenzversion
unterscheidet, statt nur zu behaupten, dass es funktioniert.

## Kontakt / Beauftragung

Vollständige, manuelle Smart-Contract-Audits (über die automatisierte
Vorprüfung durch `anchor_lint.py` hinaus) siehe [`../README.md`](../README.md)
im Hauptverzeichnis dieses Repositories.
