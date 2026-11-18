// SPDX-License-Identifier: AGPL-3.0
pragma solidity 0.8.24;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title VaultProxy - the ERC-1967 proxy of BridgeVault, deployed with the vault's initialize call
/// @notice The code moves by the vault's own UUPS upgrade; the proxy's address and storage stay for good
contract VaultProxy is ERC1967Proxy {
    constructor(address implementation, bytes memory data) ERC1967Proxy(implementation, data) {}
}
