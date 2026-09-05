// vulnerable_program.rs
//
// Absichtlich UNSICHERE Beispiel-Anchor-Programm ("Vault") zu Lehrzwecken.
// NICHT in Produktion verwenden. Enthaelt 5 klassische, real vorkommende
// Solana/Anchor-Schwachstellenklassen - siehe Kommentare "VULNERABILITY".
// Die korrigierte Version steht in fixed_program.rs.

use anchor_lang::prelude::*;

declare_id!("Vau1t1nsecure11111111111111111111111111111");

#[program]
pub mod insecure_vault {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.owner = ctx.accounts.owner.key();
        vault.balance = 0;
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;

        // VULNERABILITY 1 (unchecked arithmetic / integer overflow):
        // eine ausreichend grosse Einzahlung laesst `balance` um den u64-Bereich
        // "herumlaufen" (wrap-around) und landet wieder bei einer kleinen Zahl -
        // der Einzahler bekommt dafuer trotzdem den vollen `balance`-Zuwachs
        // gutgeschrieben, der Ueberlauf selbst wird verschwiegen.
        vault.balance = vault.balance + amount;

        **ctx.accounts.vault_lamports.lamports.borrow_mut() += amount;
        **ctx.accounts.depositor.to_account_info().lamports.borrow_mut() -= amount;
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;

        // VULNERABILITY 3 (unchecked arithmetic / integer underflow):
        // ist `amount` groesser als `vault.balance`, unterlaeuft die Subtraktion
        // den u64-Bereich und `balance` wird zu einer riesigen Zahl statt dass
        // die Transaktion fehlschlaegt - ein Angreifer kann so beliebig oft
        // "abheben", auch wenn der Vault laengst leer ist.
        vault.balance = vault.balance - amount;

        **ctx.accounts.vault_lamports.lamports.borrow_mut() -= amount;
        **ctx.accounts.destination.lamports.borrow_mut() += amount;
        Ok(())
    }

    pub fn close_vault(ctx: Context<CloseVault>) -> Result<()> {
        let vault_ai = ctx.accounts.vault.to_account_info();
        let dest_ai = ctx.accounts.destination.to_account_info();

        // VULNERABILITY 5 (manuelles Schliessen statt `close =`-Constraint):
        // die Lamports werden manuell auf 0 gesetzt, aber die Kontodaten
        // (inkl. Discriminator) bleiben unveraendert im Ledger stehen. Ohne
        // Anchors `close`-Constraint (das zusaetzlich die Daten ueberschreibt
        // und das Konto dem System-Programm zuweist) kann das Konto innerhalb
        // derselben Transaktion oder ueber eine Race-Condition noch als
        // "lebendig" gelesen/wiederbelebt werden.
        **dest_ai.lamports.borrow_mut() = dest_ai.lamports() + vault_ai.lamports();
        **vault_ai.lamports.borrow_mut() = 0;
        Ok(())
    }
}

#[account]
pub struct Vault {
    pub owner: Pubkey,
    pub balance: u64,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = owner, space = 8 + 32 + 8)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// CHECK: VULNERABILITY 2 (keine PDA-Validierung) - diesem Feld fehlt
    /// jede `seeds`/`bump`-Einschraenkung, es wird nur als rohe AccountInfo
    /// akzeptiert. Ein Aufrufer kann HIER JEDES beliebige, veraenderbare
    /// Konto einreichen, nicht nur den echten Vault-Lamport-Speicher.
    #[account(mut)]
    pub vault_lamports: AccountInfo<'info>,
    #[account(mut)]
    pub depositor: Signer<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub vault_lamports: AccountInfo<'info>,
    /// CHECK: VULNERABILITY 4 (fehlende Signer-/Owner-Pruefung) - `authority`
    /// ist nur eine rohe AccountInfo, kein `Signer<'info>`, und `vault` hat
    /// kein `has_one = authority`. Anchor erzwingt hier WEDER eine Signatur
    /// NOCH einen Abgleich mit `vault.owner` - jeder kann fremde Vaults
    /// leeren, indem er einfach den Owner-Pubkey als `authority` einreicht.
    pub authority: AccountInfo<'info>,
    #[account(mut)]
    pub destination: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct CloseVault<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub destination: AccountInfo<'info>,
}
