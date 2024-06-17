# Mithril

Mithril is a Solana full node client written in Golang with the goal of serving as a verifying node with lower hardware requirements than that of validators and RPC nodes. This project is being developed upon the foundations of [Radiance](https://github.com/firedancer-io/radiance), which was built by Richard Patel (@ripatel) and Leo Schabel.

This project is under active development. Our aim is to move rapidly with Mithril's development, hence all code is likely to be incomplete, buggy, and/or improperly tested at any particular point in time. Please check the dev branch for the latest version of the codebase. We'll begin to add documentation as Mithril begins to approach a useable state. We are currently approaching the end of Milestone 1.

Milestone 1 (Nearing completion): Full program execution capability achieved, with fully operational Solana runtime
- Reimplementation of all syscalls, with a comprehensive test suite developed and exercised; bugs found as a result fixed.
- Reimplementation of all native programs, with a comprehensive test suite developed and exercised; bugs found as a result fixed.
- Implementation of the remainder of the runtime and VM, with a comprehensive test suite also developed. Any bugs found as a result of testing and review to be fixed.

Milestone 2 (Future): Full block replay, ledger update, and RPC interface achieved. Assurance that implementation “does the right thing” also achieved.
- Full implementation of transaction (and therefore block) handling
- Work on minimal RPC interface and improve important infrastructure components (principally the accounts DB and blockstore facilities) that are necessary for data storage and retrieval.
- Development and intensive use of a robust and comprehensive ‘conformance suite’ for verification of compliance of the VM, interpreter, and runtime as a complete unit, versus all previous releases of the validator. Differential fuzzing will be used to detect differences versus relevant versions of the Labs client, and guided fuzzing will be used generally to uncover security and loss-of-availability issues. Any bugs identified during this phase will be remediated.

Milestone 3 (Future): Intensive work on system optimization
- Thorough optimization work on entire system, including on components such as the Virtual Machine and AccountsDB

Milestone 4 (Potential Future): Broadening of block retreival sources and implementation of ‘archive node’ features
- Broaden block retrieval sources beyond RPC node services (TBD how this is implemented). Current inclusion in Gossip network leads to high egress so we need to brainstorm more here
- Implementation of ‘archive node’ features, i.e. optionally seeding BitTorrent torrents and/or pushing up to Filecoin (Filecoin <-> Radiance development is currently being worked on by Triton)
