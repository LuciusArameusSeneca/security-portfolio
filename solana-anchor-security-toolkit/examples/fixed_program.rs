// fixed_program.rs
//
// Korrigierte Version von vulnerable_program.rs - behebt alle 5 dort
// markierten Schwachstellen mit idiomatischen Anchor-Bordmitteln (kein
// zusaetzliches Framework noetig). Siehe SOLANA_ANCHOR_SECURITY_GUIDE.md
// fuer die ausfuehrliche Erklaerung jeder einzelnen Korrektur.

use anchor_lang::prelude::*;

declare_id!("Vau1tSecure111111111111111111111111111111");

#[program]
pub mod secure_vault {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, bump: u8) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.owner = ctx.accounts.owner.key();
        vault.balance = 0;
        vault.bump = bump;
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;

        // FIX 1: checked_add() liefert None bei einem Ueberlauf statt still
        // "herumzulaufen" - ok_or(...)? macht daraus einen sauberen
        // Transaktionsfehler statt stiller Datenkorruption.
        vault.balance = vault
            .balance
            .checked_add(amount)
            .ok_or(VaultError::Overflow)?;

        let vault_ai = vault.to_account_info();
        let new_vault_lamports = vault_ai
            .lamports()
            .checked_add(amount)
            .ok_or(VaultError::Overflow)?;
        **vault_ai.lamports.borrow_mut() = new_vault_lamports;

        let depositor_ai = ctx.accounts.depositor.to_account_info();
        let new_depositor_lamports = depositor_ai
            .lamports()
            .checked_sub(amount)
            .ok_or(VaultError::InsufficientFunds)?;
        **depositor_ai.lamports.borrow_mut() = new_depositor_lamports;
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;

        // FIX 3: checked_sub() statt roher `-` - schlaegt sauber fehl statt
        // bei amount > balance zu unterlaufen.
        vault.balance = vault
            .balance
            .checked_sub(amount)
            .ok_or(VaultError::InsufficientFunds)?;

        let vault_ai = vault.to_account_info();
        let new_vault_lamports = vault_ai
            .lamports()
            .checked_sub(amount)
            .ok_or(VaultError::InsufficientFunds)?;
        **vault_ai.lamports.borrow_mut() = new_vault_lamports;

        let dest_ai = ctx.accounts.destination.to_account_info();
        let new_dest_lamports = dest_ai
            .lamports()
            .checked_add(amount)
            .ok_or(VaultError::Overflow)?;
        **dest_ai.lamports.borrow_mut() = new_dest_lamports;
        Ok(())
    }

    pub fn close_vault(_ctx: Context<CloseVault>) -> Result<()> {
        // FIX 5: das eigentliche Schliessen passiert bereits deklarativ ueber
        // `close = destination` im Accounts-Struct unten - kein manueller
        // Lamport-Code mehr noetig. Anchor uebernimmt: Lamports auf 0 setzen,
        // Kontodaten/Discriminator ueberschreiben (verhindert "Revival") und
        // das Konto dem System-Programm zuweisen - alles in einem
        // auditierten Schritt.
        Ok(())
    }
}

#[account]
pub struct Vault {
    pub owner: Pubkey,
    pub balance: u64,
    pub bump: u8,
}

#[error_code]
pub enum VaultError {
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Insufficient funds")]
    InsufficientFunds,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = owner,
        space = 8 + 32 + 8 + 1,
        seeds = [b"vault", owner.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    // FIX 2: `seeds`/`bump` re-derivieren die EXAKT erwartete Vault-Adresse
    // aus `vault.owner` - die Runtime lehnt jedes Konto ab, das nicht genau
    // diese PDA ist. Damit entfaellt das separate, unvalidierte
    // `vault_lamports`-Feld aus der unsicheren Version komplett: der Vault
    // selbst haelt seine Lamports.
    #[account(
        mut,
        seeds = [b"vault", vault.owner.as_ref()],
        bump = vault.bump,
    )]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub depositor: Signer<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    // FIX 2 + FIX 4 gemeinsam: `has_one = owner` laesst Anchor automatisch
    // pruefen, dass `vault.owner == owner.key()` gilt, UND `owner` ist jetzt
    // ein echter `Signer<'info>` - damit sind sowohl "keine Signatur noetig"
    // als auch "jeder kann sich als Owner ausgeben" gleichzeitig behoben.
    #[account(
        mut,
        seeds = [b"vault", owner.key().as_ref()],
        bump = vault.bump,
        has_one = owner,
    )]
    pub vault: Account<'info, Vault>,
    pub owner: Signer<'info>,
    /// CHECK: empfaengt nur Lamports, wird nie als Programmdaten gelesen -
    /// ein SystemAccount genuegt hier bewusst.
    #[account(mut)]
    pub destination: SystemAccount<'info>,
}

#[derive(Accounts)]
pub struct CloseVault<'info> {
    #[account(
        mut,
        seeds = [b"vault", owner.key().as_ref()],
        bump = vault.bump,
        has_one = owner,
        close = destination,
    )]
    pub vault: Account<'info, Vault>,
    pub owner: Signer<'info>,
    #[account(mut)]
    pub destination: SystemAccount<'info>,
}
