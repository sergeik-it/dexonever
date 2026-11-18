// SPDX-License-Identifier: AGPL-3.0
pragma solidity 0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
// OpenZeppelin 5.7 has no ReentrancyGuardUpgradeable: ReentrancyGuard keeps its flag in a namespaced slot (ERC-7201); behind
// the proxy the slot starts empty, which is not ENTERED, so the guard works without an initializer
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {BridgeConstants} from "./BridgeConstants.sol";

/// @title The bridge vault of an EVM network (BSC first): it keeps the tokens bridged to Everscale
/// @notice deposit() takes a user's tokens for Everscale; withdraw() gives tokens burned in Everscale back by the
/// signatures of the current relay round. A withdrawal never fails for good — the tokens are already burned: above the
/// instant amount or the hourly / daily limit it waits the delay and is released by anyone; without tokens in the vault
/// it waits for them. The owner (a multisig) sets the round, the tokens, the limits and the delay, unpauses and cancels a
/// queued withdrawal (the veto); a change that loosens the protection is announced first and applies after upgradeDelay,
/// the owner or a guardian may cancel it (a guardian's removal — the owner only); a guardian (a watcher) and the owner pause. The code changes in two steps: the upgrader
/// (a multisig, separate from the owner) proposes it, the owner applies exactly that code after upgradeDelay, within
/// UPGRADE_APPLY_WINDOW (a UUPS proxy: the vault's address and storage stay); after renounceUpgrades the code never
/// changes. New storage goes only after the last field
contract BridgeVault is EIP712Upgradeable, ReentrancyGuard, UUPSUpgradeable {
    using SafeERC20 for IERC20;

    struct TokenConfig {
        // 10^(decimals here - decimals in Everscale): a deposit must be a multiple of it (USDT: 10^12)
        uint256 scale;
        bool depositsEnabled;
        uint256 minDeposit;
        uint256 maxDeposit;
        // a withdrawal above it waits the delay
        uint256 instantMax;
        // what instant withdrawals may give within one hour and one day (UTC buckets)
        uint256 hourLimit;
        uint256 dayLimit;
    }

    struct Queued {
        address token;
        address recipient;
        uint256 amount;
        uint64 releaseAt;
    }

    enum Status { None, Queued, Done, Cancelled }

    bytes32 public constant WITHDRAWAL_TYPEHASH =
        keccak256("Withdrawal(uint32 round,bytes32 everEventId,address token,address recipient,uint256 amount)");
    // the values live in BridgeConstants.sol; the public ones stay readable here
    uint256 public constant MAX_SIGNERS = BridgeConstants.MAX_SIGNERS;
    uint64 public constant MIN_DELAY = BridgeConstants.MIN_DELAY;
    uint64 public constant MAX_DELAY = BridgeConstants.MAX_DELAY;
    uint64 public constant CHANGE_APPLY_WINDOW = BridgeConstants.CHANGE_APPLY_WINDOW;
    uint64 public constant UPGRADE_DELAY = BridgeConstants.UPGRADE_DELAY;
    uint64 public constant UPGRADE_APPLY_WINDOW = BridgeConstants.UPGRADE_APPLY_WINDOW;

    address public owner;
    address public pendingOwner;
    address public upgrader;
    address public pendingUpgrader;
    address public proposedCode;
    uint64 public proposedAt;
    mapping(address => bool) public guardians;
    bool public paused;

    uint32 public round;
    uint256 public threshold;
    address[] private _signers;
    mapping(uint32 => mapping(address => bool)) public isSigner;

    uint64 public delay;
    uint64 public nextDepositId;
    mapping(address => TokenConfig) private _tokens;
    mapping(bytes32 => Status) public withdrawals;
    mapping(bytes32 => Queued) public queued;
    mapping(address => mapping(uint256 => uint256)) public hourSpent;
    mapping(address => mapping(uint256 => uint256)) public daySpent;
    // how long a proposed code and an announced change wait: set by the deploy, never changed, at most UPGRADE_DELAY; 0 — they
    // apply at once
    uint64 public upgradeDelay;
    // renounced, the code never changes again
    bool public upgradesRenounced;
    // the changes the owner announced: the hash of the kind and the call → when
    mapping(bytes32 => uint64) public announcedAt;
    // a new vault takes its first token at once; every later new token is announced
    bool public firstTokenOpen;
    // the kind of each announced change (BridgeConstants.KIND_*): a guardian's removal is cancelled by the owner only
    mapping(bytes32 => uint8) public announcedKind;

    event Deposited(uint64 indexed depositId, address indexed token, address indexed sender, uint256 amount, int8 everWorkchain, bytes32 everAddress);
    event Withdrawn(bytes32 indexed everEventId, address indexed token, address indexed recipient, uint256 amount);
    event WithdrawalQueued(bytes32 indexed everEventId, address indexed token, address indexed recipient, uint256 amount, uint64 releaseAt);
    event WithdrawalCancelled(bytes32 indexed everEventId);
    event RoundSet(uint32 indexed round, address[] signers, uint256 threshold);
    event TokenSet(address indexed token, TokenConfig config);
    event DelaySet(uint64 delay);
    event GuardianSet(address indexed guardian, bool enabled);
    event Paused(address indexed by);
    event Unpaused();
    event OwnershipOffered(address indexed to);
    event OwnershipTransferred(address indexed from, address indexed to);
    event UpgraderOffered(address indexed to);
    event UpgraderTransferred(address indexed from, address indexed to);
    event CodeProposed(address indexed code, uint64 applicableAt);
    event CodeProposalRevoked(address indexed code);
    event UpgradesRenounced();
    event ChangeAnnounced(bytes32 indexed changeHash, uint8 kind, uint64 applicableAt);
    event ChangeCancelled(bytes32 indexed changeHash, address indexed by);

    error NotOwner();
    error NotGuardian();
    error IsPaused();
    error BadRound();
    error BadSigners();
    error BadSignatures();
    error BadToken();
    error BadAmount();
    error BadRecipient();
    error BadDelay();
    error AlreadyProcessed();
    error NotQueued();
    error TooEarly();
    error NotUpgrader();
    error BadCode();
    error NotAnnounced();
    error OwnerCancelsOnly();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert IsPaused();
        _;
    }

    modifier onlyUpgrader() {
        if (msg.sender != upgrader) revert NotUpgrader();
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Called once by the proxy's deploy; the owner and the upgrader are different multisigs
    function initialize(address owner_, address upgrader_, address[] calldata signers_, uint256 threshold_, uint64 delay_, uint64 upgradeDelay_)
        external
        initializer
    {
        if (owner_ == address(0)) revert NotOwner();
        if (upgradeDelay_ > UPGRADE_DELAY) revert BadDelay();
        if (upgrader_ == address(0) || upgrader_ == owner_) revert NotUpgrader();
        __EIP712_init("DEXonEVER Bridge", "1");
        owner = owner_;
        upgrader = upgrader_;
        emit OwnershipTransferred(address(0), owner_);
        emit UpgraderTransferred(address(0), upgrader_);
        _setRound(signers_, threshold_);
        _setDelay(delay_);
        upgradeDelay = upgradeDelay_;
        firstTokenOpen = true;
    }

    // ---------------------------------------------------------------- users

    /// @notice Takes `amount` of `token` for the Everscale address `everWorkchain:everAddress`
    function deposit(address token, uint256 amount, int8 everWorkchain, bytes32 everAddress) external nonReentrant whenNotPaused {
        TokenConfig storage config = _tokens[token];
        if (!config.depositsEnabled) revert BadToken();
        if (amount % config.scale != 0 || amount < config.minDeposit || amount > config.maxDeposit) revert BadAmount();
        // Everscale has the base workchain 0 and the masterchain -1: a deposit to another could never be minted there
        if (everAddress == bytes32(0) || (everWorkchain != 0 && everWorkchain != -1)) revert BadRecipient();
        uint256 before = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        // a token that takes a fee on transfer would mint in Everscale more than the vault got
        if (IERC20(token).balanceOf(address(this)) - before != amount) revert BadAmount();
        emit Deposited(nextDepositId++, token, msg.sender, amount, everWorkchain, everAddress);
    }

    /// @notice Gives `amount` of `token` to `recipient` for the Everscale withdrawal `everEventId` signed by at least
    /// `threshold` signers of the current round, in ascending order of their addresses. Above the instant amount or the
    /// limits it is queued for `delay`; without the tokens in the vault — queued without the delay (release pays it once they come)
    function withdraw(uint32 round_, bytes32 everEventId, address token, address recipient, uint256 amount, bytes[] calldata signatures)
        external
        nonReentrant
        whenNotPaused
    {
        if (round_ != round) revert BadRound();
        if (withdrawals[everEventId] != Status.None) revert AlreadyProcessed();
        TokenConfig storage config = _tokens[token];
        if (config.scale == 0) revert BadToken();
        if (recipient == address(0)) revert BadRecipient();
        if (amount == 0) revert BadAmount();
        _checkSignatures(keccak256(abi.encode(WITHDRAWAL_TYPEHASH, round_, everEventId, token, recipient, amount)), signatures);

        uint256 hour = block.timestamp / BridgeConstants.HOUR;
        uint256 day = block.timestamp / BridgeConstants.DAY;
        bool instant = amount <= config.instantMax
            && hourSpent[token][hour] + amount <= config.hourLimit
            && daySpent[token][day] + amount <= config.dayLimit;
        if (!instant) {
            _queue(everEventId, token, recipient, amount, uint64(block.timestamp) + delay);
            return;
        }
        hourSpent[token][hour] += amount;
        daySpent[token][day] += amount;
        // it was within the limits: it takes them and waits no delay, only the tokens — so what goes without the delay stays
        // within the hour and the day even when the vault is empty; the owner's veto (cancel) holds until it is released
        if (IERC20(token).balanceOf(address(this)) < amount) {
            _queue(everEventId, token, recipient, amount, uint64(block.timestamp));
            return;
        }
        withdrawals[everEventId] = Status.Done;
        IERC20(token).safeTransfer(recipient, amount);
        emit Withdrawn(everEventId, token, recipient, amount);
    }

    /// @notice Gives a queued withdrawal after its delay; anyone calls it
    function release(bytes32 everEventId) external nonReentrant whenNotPaused {
        if (withdrawals[everEventId] != Status.Queued) revert NotQueued();
        Queued memory q = queued[everEventId];
        if (block.timestamp < q.releaseAt) revert TooEarly();
        withdrawals[everEventId] = Status.Done;
        delete queued[everEventId];
        IERC20(q.token).safeTransfer(q.recipient, q.amount);
        emit Withdrawn(everEventId, q.token, q.recipient, q.amount);
    }

    // ---------------------------------------------------------------- guardians and the owner

    /// @notice Stops deposits, withdrawals and releases: one guardian or the owner is enough, only the owner unpauses
    function pause() external {
        if (!guardians[msg.sender] && msg.sender != owner) revert NotGuardian();
        paused = true;
        emit Paused(msg.sender);
    }

    /// @notice The owner unpauses
    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused();
    }

    /// @notice The owner's veto: a queued withdrawal is dropped
    function cancel(bytes32 everEventId) external onlyOwner {
        _cancel(everEventId);
    }

    /// @notice The owner's veto for a batch of queued withdrawals
    function cancelMany(bytes32[] calldata everEventIds) external onlyOwner {
        for (uint256 i = 0; i < everEventIds.length; i++) {
            _cancel(everEventIds[i]);
        }
    }

    function _cancel(bytes32 everEventId) private {
        if (withdrawals[everEventId] != Status.Queued) revert NotQueued();
        withdrawals[everEventId] = Status.Cancelled;
        delete queued[everEventId];
        emit WithdrawalCancelled(everEventId);
    }

    /// @notice The owner sets a new round of signers (see _setRound), after announcing it (_takeChange); the old round's
    /// signatures no longer count
    function setRound(address[] calldata signers_, uint256 threshold_) external onlyOwner {
        _checkRound(signers_, threshold_);
        if (_takeChange(BridgeConstants.KIND_ROUND, keccak256(abi.encode(signers_, threshold_)))) {
            _setRound(signers_, threshold_);
        }
    }

    /// @notice The owner sets a token's config. The scale of a token is set once: withdrawals in flight were counted with it.
    /// Lower limits and the deposit settings go at once, as the first token of a new vault; higher limits and a new token are
    /// announced first (_takeChange)
    function setToken(address token, TokenConfig calldata config) external onlyOwner {
        if (token == address(0) || config.scale == 0) revert BadToken();
        uint256 scale = _tokens[token].scale;
        if (scale != 0 && scale != config.scale) revert BadToken();
        if (config.minDeposit == 0 || config.minDeposit > config.maxDeposit
            || config.minDeposit % config.scale != 0 || config.maxDeposit % config.scale != 0) revert BadAmount();
        bool instant = scale == 0 ? firstTokenOpen : _tightens(_tokens[token], config);
        uint8 kind = scale == 0 ? BridgeConstants.KIND_NEW_TOKEN : BridgeConstants.KIND_TOKEN_CONFIG;
        if (!instant && !_takeChange(kind, keccak256(abi.encode(token, config)))) return;
        if (scale == 0) firstTokenOpen = false;
        _tokens[token] = config;
        emit TokenSet(token, config);
    }

    /// @notice The owner sets the delay of a queued withdrawal, from MIN_DELAY to MAX_DELAY: a longer one at once, a shorter
    /// one after announcing it (_takeChange)
    function setDelay(uint64 delay_) external onlyOwner {
        _checkDelay(delay_);
        if (delay_ >= delay || _takeChange(BridgeConstants.KIND_DELAY, keccak256(abi.encode(delay_)))) {
            _setDelay(delay_);
        }
    }

    /// @notice The owner adds a guardian at once or removes one after announcing it (_takeChange)
    function setGuardian(address guardian, bool enabled) external onlyOwner {
        if (guardian == address(0)) revert NotGuardian();
        if (enabled || !guardians[guardian] || _takeChange(BridgeConstants.KIND_GUARDIAN, keccak256(abi.encode(guardian, enabled)))) {
            guardians[guardian] = enabled;
            emit GuardianSet(guardian, enabled);
        }
    }

    /// @notice The owner or a guardian drops an announced change; a guardian's removal is cancelled by the owner only
    function cancelChange(bytes32 changeHash) external {
        if (!guardians[msg.sender] && msg.sender != owner) revert NotGuardian();
        if (announcedAt[changeHash] == 0) revert NotAnnounced();
        if (msg.sender != owner && announcedKind[changeHash] == BridgeConstants.KIND_GUARDIAN) revert OwnerCancelsOnly();
        delete announcedAt[changeHash];
        delete announcedKind[changeHash];
        emit ChangeCancelled(changeHash, msg.sender);
    }

    /// @notice The owner offers the ownership to `to`; it takes effect on acceptOwnership
    function transferOwnership(address to) external onlyOwner {
        pendingOwner = to;
        emit OwnershipOffered(to);
    }

    /// @notice The offered owner accepts. The upgrader cannot take the vault: the roles stay apart, as in the Everscale root
    function acceptOwnership() external {
        if (msg.sender != pendingOwner || msg.sender == address(0) || msg.sender == upgrader) revert NotOwner();
        emit OwnershipTransferred(owner, msg.sender);
        owner = msg.sender;
        pendingOwner = address(0);
    }

    // ---------------------------------------------------------------- the upgrader

    /// @notice The upgrader proposes a new code (a deployed implementation) to apply after upgradeDelay; a new proposal
    /// replaces the old one. Not after renounceUpgrades
    function proposeCode(address code) external onlyUpgrader {
        if (upgradesRenounced) revert NotUpgrader();
        if (code.code.length == 0) revert BadCode();
        proposedCode = code;
        proposedAt = uint64(block.timestamp);
        emit CodeProposed(code, proposedAt + upgradeDelay);
    }

    /// @notice The upgrader gives up changing the code for good: a proposed code is revoked, nothing is proposed or applied again
    function renounceUpgrades() external onlyUpgrader {
        if (upgradesRenounced) revert NotUpgrader();
        upgradesRenounced = true;
        if (proposedCode != address(0)) {
            emit CodeProposalRevoked(proposedCode);
            proposedCode = address(0);
            proposedAt = 0;
        }
        emit UpgradesRenounced();
    }

    /// @notice The upgrader revokes the proposed code
    function revokeCode() external onlyUpgrader {
        if (proposedCode == address(0)) revert BadCode();
        emit CodeProposalRevoked(proposedCode);
        proposedCode = address(0);
        proposedAt = 0;
    }

    /// @notice The upgrader offers its role to `to`; it takes effect on acceptUpgrader
    function transferUpgrader(address to) external onlyUpgrader {
        pendingUpgrader = to;
        emit UpgraderOffered(to);
    }

    /// @notice The offered upgrader accepts. The owner cannot become the upgrader: the roles stay apart
    function acceptUpgrader() external {
        if (msg.sender != pendingUpgrader || msg.sender == address(0) || msg.sender == owner) revert NotUpgrader();
        emit UpgraderTransferred(upgrader, msg.sender);
        upgrader = msg.sender;
        pendingUpgrader = address(0);
    }

    /// @notice upgradeToAndCall (UUPSUpgradeable) applies only the proposed code, by the owner, within its window
    function _authorizeUpgrade(address code) internal override onlyOwner {
        if (upgradesRenounced) revert NotUpgrader();
        if (code != proposedCode || code == address(0)) revert BadCode();
        if (block.timestamp < proposedAt + upgradeDelay) revert TooEarly();
        if (block.timestamp > proposedAt + upgradeDelay + UPGRADE_APPLY_WINDOW) revert BadCode();
        proposedCode = address(0);
        proposedAt = 0;
    }

    // ---------------------------------------------------------------- views

    /// @notice The signers of the current round
    function signers() external view returns (address[] memory) {
        return _signers;
    }

    /// @notice A token's config
    function tokenConfig(address token) external view returns (TokenConfig memory) {
        return _tokens[token];
    }

    /// @notice The EIP-712 digest the relays sign
    function withdrawalDigest(uint32 round_, bytes32 everEventId, address token, address recipient, uint256 amount) external view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(WITHDRAWAL_TYPEHASH, round_, everEventId, token, recipient, amount)));
    }

    // ---------------------------------------------------------------- internal

    function _queue(bytes32 everEventId, address token, address recipient, uint256 amount, uint64 releaseAt) private {
        withdrawals[everEventId] = Status.Queued;
        queued[everEventId] = Queued(token, recipient, amount, releaseAt);
        emit WithdrawalQueued(everEventId, token, recipient, amount, releaseAt);
    }

    function _checkSignatures(bytes32 structHash, bytes[] calldata signatures) private view {
        bytes32 digest = _hashTypedDataV4(structHash);
        address last = address(0);
        uint256 count = 0;
        for (uint256 i = 0; i < signatures.length; i++) {
            // OpenZeppelin's recover refuses malleable signatures (s in the upper half) and a zero signer
            address signer = ECDSA.recover(digest, signatures[i]);
            if (signer <= last || !isSigner[round][signer]) revert BadSignatures();
            last = signer;
            count++;
        }
        if (count < threshold) revert BadSignatures();
    }

    /// @notice A round's signers are in ascending order without repeats, its threshold is more than a half
    function _checkRound(address[] memory signers_, uint256 threshold_) private pure {
        uint256 n = signers_.length;
        if (n == 0 || n > MAX_SIGNERS || threshold_ * 2 <= n || threshold_ > n) revert BadSigners();
        address last = address(0);
        for (uint256 i = 0; i < n; i++) {
            if (signers_[i] <= last) revert BadSigners();
            last = signers_[i];
        }
    }

    /// @notice A new round (_checkRound)
    function _setRound(address[] memory signers_, uint256 threshold_) private {
        _checkRound(signers_, threshold_);
        uint32 next = round + 1;
        for (uint256 i = 0; i < signers_.length; i++) {
            isSigner[next][signers_[i]] = true;
        }
        round = next;
        threshold = threshold_;
        _signers = signers_;
        emit RoundSet(next, signers_, threshold_);
    }

    function _checkDelay(uint64 delay_) private pure {
        if (delay_ < MIN_DELAY || delay_ > MAX_DELAY) revert BadDelay();
    }

    function _setDelay(uint64 delay_) private {
        _checkDelay(delay_);
        delay = delay_;
        emit DelaySet(delay_);
    }

    /// @notice Whether an announced change applies now: announced at least upgradeDelay ago, within CHANGE_APPLY_WINDOW after
    /// it (then it is used up). Otherwise it is announced (anew after its window) and false returned; before its delay — refused
    function _takeChange(uint8 kind, bytes32 call) private returns (bool) {
        bytes32 changeHash = keccak256(abi.encode(kind, call));
        uint64 at = announcedAt[changeHash];
        if (at != 0 && block.timestamp <= at + upgradeDelay + CHANGE_APPLY_WINDOW) {
            if (block.timestamp < at + upgradeDelay) revert TooEarly();
            delete announcedAt[changeHash];
            delete announcedKind[changeHash];
            return true;
        }
        announcedAt[changeHash] = uint64(block.timestamp);
        announcedKind[changeHash] = kind;
        emit ChangeAnnounced(changeHash, kind, uint64(block.timestamp) + upgradeDelay);
        return false;
    }

    /// @notice Whether a token's new config only lowers its withdrawal limits
    function _tightens(TokenConfig storage old, TokenConfig calldata config) private view returns (bool) {
        return config.instantMax <= old.instantMax && config.hourLimit <= old.hourLimit && config.dayLimit <= old.dayLimit;
    }
}
