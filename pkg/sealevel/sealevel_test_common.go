package sealevel

func instructionAcctsFromAccountMetas(instrAcctMetas []AccountMeta, txAccounts TransactionAccounts) []InstructionAccount {
	var instrAccts []InstructionAccount

	for instrAcctIdx, accountMeta := range instrAcctMetas {
		idxInTx := -1
		for pos, acct := range txAccounts.Accounts {
			a := *acct
			if a.Key == accountMeta.Pubkey {
				idxInTx = pos
			}
		}
		if idxInTx == -1 {
			idxInTx = len(txAccounts.Accounts)
		}

		accts := instrAccts[:instrAcctIdx]
		idxInCallee := -1
		for pos, instrAcct := range accts {
			if instrAcct.IndexInTransaction == uint64(idxInTx) {
				idxInCallee = pos
			}
		}
		if idxInCallee == -1 {
			idxInCallee = instrAcctIdx
		}

		newInstrAcct := InstructionAccount{IndexInTransaction: uint64(idxInTx), IndexInCaller: uint64(idxInTx), IndexInCallee: uint64(idxInCallee), IsSigner: accountMeta.IsSigner, IsWritable: accountMeta.IsWritable}
		instrAccts = append(instrAccts, newInstrAcct)
	}

	return instrAccts
}
