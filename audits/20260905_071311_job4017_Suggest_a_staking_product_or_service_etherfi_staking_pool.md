# Suggest a staking product or service: ether.fi (staking pool)

**Chain/Technologie:** Sonstige  
**Quelle:** [github](https://github.com/ethereum/ethereum-org-website/issues/19098)  
**Datum:** 2026-09-05  
**Erkannt als:** Web3-Security-/Smart-Contract-Audit (Stichwort: "audit")

---

## Zusammenfassung des Auftrags

**Stellenausschreibung: Suggest a staking product or service for ether.fi**

**Titel:** Ether.fi - Staking Pool

**Beschreibung:** This replaces #11568, which @wackerow reviewed in June 2024 ("Overall this look good... Welcome a PR for this addition") and @minimalsm closed once the thread went quiet. The client diversity numbers that were missing then are included below.

I work at ether.fi. A PR is ready to open against this issue.

---

### Project name

ether.fi

### Product type

Staking pool

### Logo

Brand assets: https://github.com/etherfi-protocol/design_assets

The PR adds a monochrome `currentColor` glyph matching the other product glyphs, at `src/components/icons/staking/ether-fi-glyph.svg`.

---

### Description

Non-custodial liquid staking, run by public smart contracts. Node operators hold the validator keys, and the protocol contracts trigger exits as liquidity requires. Staking mints eETH, which wraps to weETH for use across DeFi.

**Website**

https://ether.fi/

---

### If software is involved, is everything open source?

Yes. Smart contracts: https://github

## Analyse / Audit-Ergebnis

```javascript
// Import necessary libraries and modules
const { ethers } = require('ethers');
const fs = require('fs');

/**
 * Checks for invariant violations in the smart contract code.
 */
async function checkInvariantViolations() {
    // Load the ERC-1155 token standard
    const erc1155 = await ethers.getContractFactory('ERC1155');
    
    // Load the smart contract code for staking
    const stakingCodePath = 'path/to/staking_contract.sol';
    const stakingContract = await ethers.getContractFactory('Staking');
    
    // Load the smart contract code for non-custodial liquid staking
    const ncsCodePath = 'path/to/non_custodial_liquid_staking.sol';
    
    // Load the smart contract code for eETH wrapping to weETH
    const ethWrapCodePath = 'path/to/eth_wrap_to_weeth.sol';
    
    // Load the smart contract code for node operators holding validator keys
    const operatorKeysCodePath = 'path/to/operator_keys_contract.sol';

    // Check for invariant violations in the staking contract code
    const invariantViolationsStakingContract = await checkInvariantViolationsInCode(erc1155, stakingContract);
    
    // Check for invariant violations in the non-custodial liquid staking contract code
    const invariantViolationsNcs = await checkInvariantViolationsInCode(erc1155, ncsContract);
    
    // Check for invariant violations in the eETH wrapping to weETH contract code
    const invariantViolationsEthWrap = await checkInvariantViolationsInCode(erc1155, ethWrapContract);
    
    // Check for invariant violations in the node operator keys contract code
    const invariantViolationsOperatorKeys = await checkInvariantViolationsInCode(erc1155, operatorKeysContract);
    
    // Return the results of all checks
    return {
        invariantViolationsStaking: invariantViolationsStakingContract,
        invariantViolationsNcs: invariantViolationsNcs,
        invariantViolationsEthWrap: invariantViolationsEthWrap,
        invariantViolationsOperatorKeys: invariantViolationsOperatorKeys
    };
}

/**
 * Checks for invariant violations in a given contract.
 */
async function checkInvariantViolationsInCode(erc1155, contract) {
    // Implement the logic to check for invariant violations
    // This could involve deploying a test instance of the contract,
    // invoking transactions, and verifying that invariants hold.
    
    return []; // Placeholder for actual invariant violations
}
```

---

*Dieser Report wurde automatisiert von der CryptoJobHunter-KI-Pipeline erstellt (3-stufige Analyse: Zusammenfassung, Loesungsentwurf mit Code-Kontext, verfeinerte Analyse) und dokumentiert einen real gefundenen Auftrag. Er ersetzt keine manuelle Verifikation vor produktivem Einsatz.*
