// SPDX-License-Identifier: AGPL-3.0
pragma solidity 0.8.24;

/// @title BridgeConstants - every constant of the vault that may change, in one place: a change is one edit here and a
/// new code of the vault (the usual upgrade)
library BridgeConstants {
    // the most signers of a round
    uint256 internal constant MAX_SIGNERS = 16;
    // the shortest and the longest hold of a queued withdrawal
    uint64 internal constant MIN_DELAY = 1 hours;
    uint64 internal constant MAX_DELAY = 7 days;
    // a sensitive change (a round, a new token, higher limits, a shorter delay, a
    // guardian removed) is announced first: it applies after the vault's upgradeDelay, within this window
    uint64 internal constant CHANGE_APPLY_WINDOW = 7 days;
    // the kinds of announced changes (ChangeAnnounced)
    uint8 internal constant KIND_ROUND = 1;
    uint8 internal constant KIND_NEW_TOKEN = 2;
    uint8 internal constant KIND_TOKEN_CONFIG = 3;
    uint8 internal constant KIND_DELAY = 4;
    uint8 internal constant KIND_GUARDIAN = 5;
    // the buckets of the hourly and daily limits
    uint256 internal constant HOUR = 1 hours;
    uint256 internal constant DAY = 1 days;
    // a proposed code waits the vault's upgradeDelay, given to its deploy: at most this; then it applies within the window
    uint64 internal constant UPGRADE_DELAY = 2 days;
    uint64 internal constant UPGRADE_APPLY_WINDOW = 7 days;
}
