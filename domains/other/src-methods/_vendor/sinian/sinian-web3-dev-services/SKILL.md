---
name: web3-dev-services
description: >-
  Web3开发服务全栈技能 — EVM链/Solana链智能合约开发、DApp/DeFi项目定制、Web3官网/白皮书、合约审计、Bitget代币上架、KOL资源对接、海外老外站台等全链路Web3项目服务。覆盖Solidity/Rust/Move合约开发、UniswapV3/PancakeSwap/Raydium DeFi协议集成、React/Next.js DApp前端、SEO优化官网、Tokenomics白皮书、CertiK/SlowMist审计对接、CEX上币全流程、Twitter/YouTube/TikTok KOL矩阵、海外社区运营与站台。用于Web3项目从0到1的全流程开发与上线服务。
version: 1.0.0
author: 思念 (狗盾思念)
---

# SKILL: Web3开发服务 — 全栈项目定制与上线

> **AI LOAD INSTRUCTION**: 本技能覆盖Web3项目从零到上线的全流程服务能力。当用户提到Web3开发、合约开发、DApp、DeFi、代币上币、白皮书、合约审计、KOL推广、海外站台等需求时，加载本技能。核心能力包括：EVM链(Solidity)与Solana链(Rust)智能合约开发、DApp/DeFi项目全栈定制、Web3官网与白皮书设计开发、合约安全审计对接、Bitget等CEX代币上架全流程、KOL矩阵资源对接、海外社区运营与老外站台。本技能为商业化服务技能，聚焦实际交付能力。

---

## 0. RELATED ROUTING

- [sinian-omnipotent](../sinian-omnipotent/SKILL.md) — 思念全能安全技能集，Web3项目的安全审计与渗透测试支撑
- [ai-llm-attack-surface](../ai-llm-attack-surface/SKILL.md) — AI Agent与Web3项目集成时的攻击面评估
- [supply-chain-attacks](../supply-chain-attacks/SKILL.md) — Web3项目NPM/PyPI供应链安全
- [telegram-mini-app-bot-security](../telegram-mini-app-bot-security/SKILL.md) — Telegram Mini App + TON生态安全（Web3社交裂变场景）

---

## 1. 技术栈全景

### 1.1 核心能力矩阵

| 服务类别 | 技术栈 | 交付周期 | 质量保障 |
|----------|--------|----------|----------|
| EVM链合约开发 | Solidity / Hardhat / Foundry / OpenZeppelin | 2-6周 | 多轮审计+测试覆盖率>95% |
| Solana链合约开发 | Rust / Anchor / Solana SDK / Seahorse | 2-6周 | Program测试+本地验证 |
| DApp前端开发 | React/Next.js + ethers.js/v6 + wagmi/viem + Web3Modal | 2-8周 | 响应式+多钱包+EIP-6963 |
| DeFi协议定制 | UniswapV3/PancakeSwap/Raydium/Orca fork + 自定义AMM | 4-12周 | 滑点保护+闪电贷防护+经济模型验证 |
| Web3官网 | Next.js + Framer Motion + TailwindCSS + SEO优化 | 1-4周 | Lighthouse 90+ + 多语言 |
| 白皮书 | LaTeX/InDesign/Figma + Tokenomics建模 | 1-3周 | 学术级排版+经济模型验证 |
| 合约审计 | 自动化(Slither/Mythril/Aderyn) + 人工审计 + 外部审计对接 | 1-4周 | OWASP SWC + 四大审计所对接 |
| 代币上架 | Bitget/Gate/MEXC/Bybit等CEX上币全流程 | 4-12周 | 合规文档+项目包装+商务对接 |
| KOL资源 | Twitter/YouTube/TikTok/Telegram KOL矩阵 | 按需 | 精准匹配+数据回溯+ROI保障 |
| 海外站台 | 海外社区运营/AMA/PR/品牌背书 | 按需 | 英语母语团队+海外资源 |

### 1.2 EVM链技术栈详解

```
Solidity ^0.8.24
├── 编译框架: Hardhat / Foundry / Remix IDE
├── 合约标准: ERC-20 / ERC-721 / ERC-1155 / ERC-4626 / ERC-4337(AA) / ERC-6551(TBA)
├── 安全库: OpenZeppelin Contracts v5.x / Solady / ERC721A
├── 升级模式: UUPS / Transparent Proxy / Diamond Pattern(EIP-2535)
├── 测试框架: Hardhat Test / Foundry Forge / Waffle / Echidna(Fuzzing)
├── Gas优化: 汇编优化 / SSTORE2 / CREATE2 / 不可变变量
├── 跨链桥: LayerZero / Chainlink CCIP / Wormhole / Axelar
├── Oracle: Chainlink / Pyth / Redstone / Tellor
├── 验证器: Etherscan API / Sourcify / Blockscout
└── 部署: Hardhat Ignition / Foundry Script / Multicall
```

### 1.3 Solana链技术栈详解

```
Rust + Anchor Framework
├── 开发框架: Anchor v0.30+ / Solana SDK / Seahorse(Python→Rust)
├── Program类型: Native Rust / Anchor Program / SPL Token
├── Token标准: SPL Token / Token-2022 / Metaplex NFT
├── DeFi集成: Raydium / Orca / Jupiter / Meteora / Kamino
├── 测试框架: Anchor Test / Solana Program Test / Banks Client
├── 账户模型: PDA(Program Derived Address) / CPI(Cross-Program Invocation)
├── 压缩NFT: Bubblegum / Metaplex Compressed NFT
├── 跨链: Wormhole / Mayan Swap / deBridge
├── Oracle: Pyth / Switchboard
└── 部署: Solana CLI / Anchor Deploy / Turbin3
```

---

## 2. EVM链 & Solana链智能合约开发

### 2.1 EVM智能合约开发

#### 2.1.1 代币合约

**标准ERC-20代币（含高级功能）**：

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title 自定义ERC-20代币 — 含销毁/投票/黑名单/交易限制/反巨鲸
/// @custom:security-contact audit@example.com
contract CustomToken is ERC20, ERC20Burnable, ERC20Permit, Ownable, ReentrancyGuard {
    // === 状态变量 ===
    uint256 public constant MAX_SUPPLY = 1_000_000_000 * 10**18; // 10亿
    uint256 public maxTxAmount;               // 单笔最大交易量
    uint256 public maxWalletAmount;           // 单钱包最大持仓
    bool public tradingEnabled;               // 交易开关
    bool public limitsEnabled = true;         // 限制开关
    
    mapping(address => bool) public isBlacklisted;
    mapping(address => bool) public isExcludedFromLimits;
    
    // === 事件 ===
    event TradingEnabled(uint256 timestamp);
    event BlacklistUpdated(address indexed account, bool status);
    event LimitsUpdated(uint256 maxTx, uint256 maxWallet);
    
    // === 手续费机制（可扩展） ===
    uint256 public buyFee = 0;   // 0.5% = 50
    uint256 public sellFee = 0;
    uint256 public feeDenominator = 10000;
    address public feeReceiver;
    mapping(address => bool) public isExcludedFromFees;
    
    constructor(
        string memory name,
        string memory symbol,
        address initialOwner,
        address _feeReceiver
    ) ERC20(name, symbol) ERC20Permit(name) Ownable(initialOwner) {
        feeReceiver = _feeReceiver;
        maxTxAmount = MAX_SUPPLY;
        maxWalletAmount = MAX_SUPPLY;
        
        // 预分配排除限制
        isExcludedFromLimits[initialOwner] = true;
        isExcludedFromLimits[address(this)] = true;
        isExcludedFromLimits[address(0)] = true;
        isExcludedFromFees[initialOwner] = true;
        isExcludedFromFees[address(this)] = true;
    }
    
    // === 转账钩子 ===
    function _update(address from, address to, uint256 value) internal virtual override {
        // 黑名单检查
        require(!isBlacklisted[from] && !isBlacklisted[to], "Blacklisted");
        
        if (from != address(0) && to != address(0)) {
            // 交易限制检查
            if (limitsEnabled && !isExcludedFromLimits[from] && !isExcludedFromLimits[to]) {
                require(tradingEnabled, "Trading disabled");
                require(value <= maxTxAmount, "Exceeds max tx");
                if (to != address(0)) {
                    require(balanceOf(to) + value <= maxWalletAmount, "Exceeds max wallet");
                }
            }
            
            // 手续费处理
            uint256 fee = 0;
            bool isBuy = _isBuy(from);
            bool isSell = _isSell(to);
            
            if (!isExcludedFromFees[from] && !isExcludedFromFees[to]) {
                if (isBuy && buyFee > 0) {
                    fee = (value * buyFee) / feeDenominator;
                } else if (isSell && sellFee > 0) {
                    fee = (value * sellFee) / feeDenominator;
                }
            }
            
            if (fee > 0) {
                super._update(from, feeReceiver, fee);
                value -= fee;
            }
        }
        super._update(from, to, value);
    }
    
    function _isBuy(address from) internal view returns (bool) {
        // 从LP买入逻辑：判断from是否为DEX pair地址
        return from != address(0) && !isExcludedFromFees[from];
    }
    
    function _isSell(address to) internal view returns (bool) {
        return to != address(0) && !isExcludedFromFees[to];
    }
    
    // === 管理函数 ===
    function enableTrading() external onlyOwner {
        tradingEnabled = true;
        emit TradingEnabled(block.timestamp);
    }
    
    function setBlacklist(address account, bool status) external onlyOwner {
        isBlacklisted[account] = status;
        emit BlacklistUpdated(account, status);
    }
    
    function setLimits(uint256 _maxTx, uint256 _maxWallet) external onlyOwner {
        maxTxAmount = _maxTx;
        maxWalletAmount = _maxWallet;
        emit LimitsUpdated(_maxTx, _maxWallet);
    }
    
    function setFees(uint256 _buyFee, uint256 _sellFee) external onlyOwner {
        require(_buyFee <= 1000 && _sellFee <= 1000, "Fee too high"); // 最大10%
        buyFee = _buyFee;
        sellFee = _sellFee;
    }
}
```

**ERC-721 NFT合约（含白名单/预售/版税）**：

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Royalty.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title NFT Collection — 白名单Merkle Tree + 预售 + 版税 + 盲盒揭示
contract NFTCollection is ERC721, ERC721Enumerable, ERC721Royalty, Ownable, ReentrancyGuard {
    using Strings for uint256;
    
    uint256 public constant MAX_SUPPLY = 10000;
    uint256 public constant MAX_PER_WALLET = 10;
    uint256 public constant WHITELIST_PRICE = 0.05 ether;
    uint256 public constant PUBLIC_PRICE = 0.08 ether;
    
    bytes32 public merkleRoot;
    string public baseURI;
    string public unrevealedURI;
    bool public revealed;
    bool public whitelistMintOpen;
    bool public publicMintOpen;
    
    mapping(address => uint256) public whitelistMinted;
    mapping(address => uint256) public publicMinted;
    
    event Minted(address indexed to, uint256 tokenId, bool isWhitelist);
    event Revealed(string baseURI);
    
    constructor(
        string memory _name,
        string memory _symbol,
        string memory _unrevealedURI,
        address royaltyReceiver,
        uint96 royaltyFeeNumerator  // 如 500 = 5%
    ) ERC721(_name, _symbol) Ownable(msg.sender) {
        unrevealedURI = _unrevealedURI;
        _setDefaultRoyalty(royaltyReceiver, royaltyFeeNumerator);
    }
    
    // === 白名单铸造 ===
    function whitelistMint(bytes32[] calldata proof, uint256 quantity) 
        external payable nonReentrant {
        require(whitelistMintOpen, "Whitelist mint closed");
        require(totalSupply() + quantity <= MAX_SUPPLY, "Sold out");
        require(msg.value >= WHITELIST_PRICE * quantity, "Insufficient ETH");
        require(whitelistMinted[msg.sender] + quantity <= MAX_PER_WALLET, "Exceeds limit");
        
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender));
        require(MerkleProof.verify(proof, merkleRoot, leaf), "Invalid proof");
        
        whitelistMinted[msg.sender] += quantity;
        _batchMint(msg.sender, quantity);
        emit Minted(msg.sender, totalSupply(), true);
    }
    
    // === 公开铸造 ===
    function publicMint(uint256 quantity) external payable nonReentrant {
        require(publicMintOpen, "Public mint closed");
        require(totalSupply() + quantity <= MAX_SUPPLY, "Sold out");
        require(msg.value >= PUBLIC_PRICE * quantity, "Insufficient ETH");
        require(publicMinted[msg.sender] + quantity <= MAX_PER_WALLET, "Exceeds limit");
        
        publicMinted[msg.sender] += quantity;
        _batchMint(msg.sender, quantity);
        emit Minted(msg.sender, totalSupply(), false);
    }
    
    // === 批量铸造 ===
    function _batchMint(address to, uint256 quantity) internal {
        uint256 currentId = totalSupply();
        for (uint256 i = 0; i < quantity; i++) {
            _safeMint(to, currentId + i + 1);
        }
    }
    
    // === 揭示 ===
    function reveal(string calldata _baseURI) external onlyOwner {
        revealed = true;
        baseURI = _baseURI;
        emit Revealed(_baseURI);
    }
    
    // === Token URI ===
    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        _requireOwned(tokenId);
        if (!revealed) return unrevealedURI;
        return string(abi.encodePacked(baseURI, tokenId.toString(), ".json"));
    }
    
    // === 管理函数 ===
    function setMerkleRoot(bytes32 _root) external onlyOwner { merkleRoot = _root; }
    function toggleWhitelistMint() external onlyOwner { whitelistMintOpen = !whitelistMintOpen; }
    function togglePublicMint() external onlyOwner { publicMintOpen = !publicMintOpen; }
    function withdraw() external onlyOwner {
        (bool success, ) = msg.sender.call{value: address(this).balance}("");
        require(success, "Transfer failed");
    }
    
    // === 必需覆写 ===
    function _update(address to, uint256 tokenId, address auth) 
        internal override(ERC721, ERC721Enumerable) returns (address) {
        return super._update(to, tokenId, auth);
    }
    
    function _increaseBalance(address account, uint128 value) 
        internal override(ERC721, ERC721Enumerable) {
        super._increaseBalance(account, value);
    }
    
    function supportsInterface(bytes4 interfaceId) 
        public view override(ERC721, ERC721Enumerable, ERC721Royalty) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}
```

#### 2.1.2 DeFi合约开发

**UniswapV3风格AMM（简化版）**：

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title 简化AMM（恒定乘积 x*y=k）
contract SimpleAMM {
    using SafeERC20 for IERC20;
    
    IERC20 public immutable token0;
    IERC20 public immutable token1;
    uint256 public reserve0;
    uint256 public reserve1;
    uint256 public totalLiquidity;
    
    mapping(address => uint256) public liquidityOf;
    mapping(address => mapping(address => uint256)) public allowances;
    
    event Mint(address indexed sender, uint256 amount0, uint256 amount1, uint256 liquidity);
    event Burn(address indexed sender, uint256 amount0, uint256 amount1, uint256 liquidity);
    event Swap(address indexed sender, uint256 amountIn, uint256 amountOut, bool isToken0);
    
    constructor(address _token0, address _token1) {
        token0 = IERC20(_token0);
        token1 = IERC20(_token1);
    }
    
    /// @notice 添加流动性
    function addLiquidity(uint256 amount0Desired, uint256 amount1Desired) 
        external returns (uint256 liquidity) {
        // 计算最优数量
        (uint256 amount0, uint256 amount1) = _calculateOptimalAmounts(amount0Desired, amount1Desired);
        
        token0.safeTransferFrom(msg.sender, address(this), amount0);
        token1.safeTransferFrom(msg.sender, address(this), amount1);
        
        if (totalLiquidity == 0) {
            liquidity = Math.sqrt(amount0 * amount1) - 1000; // 锁定最小流动性
        } else {
            uint256 liquidity0 = (amount0 * totalLiquidity) / reserve0;
            uint256 liquidity1 = (amount1 * totalLiquidity) / reserve1;
            liquidity = liquidity0 < liquidity1 ? liquidity0 : liquidity1;
        }
        
        require(liquidity > 0, "INSUFFICIENT_LIQUIDITY");
        liquidityOf[msg.sender] += liquidity;
        totalLiquidity += liquidity;
        reserve0 += amount0;
        reserve1 += amount1;
        
        emit Mint(msg.sender, amount0, amount1, liquidity);
    }
    
    /// @notice 移除流动性
    function removeLiquidity(uint256 liquidity) 
        external returns (uint256 amount0, uint256 amount1) {
        require(liquidityOf[msg.sender] >= liquidity, "INSUFFICIENT_LIQUIDITY");
        
        amount0 = (liquidity * reserve0) / totalLiquidity;
        amount1 = (liquidity * reserve1) / totalLiquidity;
        
        liquidityOf[msg.sender] -= liquidity;
        totalLiquidity -= liquidity;
        reserve0 -= amount0;
        reserve1 -= amount1;
        
        token0.safeTransfer(msg.sender, amount0);
        token1.safeTransfer(msg.sender, amount1);
        
        emit Burn(msg.sender, amount0, amount1, liquidity);
    }
    
    /// @notice 兑换（token0→token1 或 token1→token0）
    function swap(uint256 amountIn, bool isToken0, uint256 minAmountOut) 
        external returns (uint256 amountOut) {
        (uint256 reserveIn, uint256 reserveOut) = isToken0 
            ? (reserve0, reserve1) : (reserve1, reserve0);
        
        // 恒定乘积：x*y=k => (x+dx)*(y-dy)=k => dy = y*dx/(x+dx)
        uint256 amountInWithFee = amountIn * 997; // 0.3% fee
        amountOut = (reserveOut * amountInWithFee) / (reserve0 * 1000 + amountInWithFee);
        require(amountOut >= minAmountOut, "SLIPPAGE");
        
        if (isToken0) {
            token0.safeTransferFrom(msg.sender, address(this), amountIn);
            reserve0 += amountIn;
            reserve1 -= amountOut;
            token1.safeTransfer(msg.sender, amountOut);
        } else {
            token1.safeTransferFrom(msg.sender, address(this), amountIn);
            reserve1 += amountIn;
            reserve0 -= amountOut;
            token0.safeTransfer(msg.sender, amountOut);
        }
        
        emit Swap(msg.sender, amountIn, amountOut, isToken0);
        require(reserve0 * reserve1 >= 0, "K");
    }
    
    function _calculateOptimalAmounts(uint256 amount0Desired, uint256 amount1Desired)
        internal view returns (uint256 amount0, uint256 amount1) {
        if (reserve0 == 0 && reserve1 == 0) {
            return (amount0Desired, amount1Desired);
        }
        uint256 amount1Optimal = (amount0Desired * reserve1) / reserve0;
        if (amount1Optimal <= amount1Desired) {
            return (amount0Desired, amount1Optimal);
        }
        uint256 amount0Optimal = (amount1Desired * reserve0) / reserve1;
        return (amount0Optimal, amount1Desired);
    }
}
```

**质押挖矿合约（Staking）**：

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Staking Pool — 质押ERC-20获得奖励代币
contract StakingPool is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;
    
    IERC20 public stakingToken;    // 质押代币
    IERC20 public rewardToken;     // 奖励代币
    
    uint256 public rewardRate;           // 每秒每个质押代币的奖励
    uint256 public totalStaked;
    uint256 public lastUpdateTime;
    uint256 public rewardPerTokenStored;
    uint256 public lockPeriod = 7 days;  // 锁仓期
    uint256 public earlyUnstakeFee = 500; // 5%提前提取手续费
    
    struct StakeInfo {
        uint256 amount;
        uint256 rewardPerTokenPaid;
        uint256 rewards;
        uint256 stakedAt;
    }
    mapping(address => StakeInfo) public stakes;
    
    event Staked(address indexed user, uint256 amount);
    event Unstaked(address indexed user, uint256 amount, uint256 reward);
    event RewardPaid(address indexed user, uint256 reward);
    
    constructor(address _stakingToken, address _rewardToken, uint256 _rewardRate) 
        Ownable(msg.sender) {
        stakingToken = IERC20(_stakingToken);
        rewardToken = IERC20(_rewardToken);
        rewardRate = _rewardRate;
    }
    
    modifier updateReward(address account) {
        rewardPerTokenStored = rewardPerToken();
        lastUpdateTime = block.timestamp;
        if (account != address(0)) {
            stakes[account].rewards = earned(account);
            stakes[account].rewardPerTokenPaid = rewardPerTokenStored;
        }
        _;
    }
    
    function rewardPerToken() public view returns (uint256) {
        if (totalStaked == 0) return rewardPerTokenStored;
        return rewardPerTokenStored + 
            (rewardRate * (block.timestamp - lastUpdateTime) * 1e18) / totalStaked;
    }
    
    function earned(address account) public view returns (uint256) {
        return (stakes[account].amount * 
            (rewardPerToken() - stakes[account].rewardPerTokenPaid)) / 1e18 
            + stakes[account].rewards;
    }
    
    function stake(uint256 amount) external nonReentrant updateReward(msg.sender) {
        require(amount > 0, "Amount = 0");
        stakes[msg.sender].amount += amount;
        stakes[msg.sender].stakedAt = block.timestamp;
        totalStaked += amount;
        stakingToken.safeTransferFrom(msg.sender, address(this), amount);
        emit Staked(msg.sender, amount);
    }
    
    function unstake(uint256 amount) external nonReentrant updateReward(msg.sender) {
        require(amount > 0 && stakes[msg.sender].amount >= amount, "Invalid amount");
        
        uint256 fee = 0;
        if (block.timestamp < stakes[msg.sender].stakedAt + lockPeriod) {
            fee = (amount * earlyUnstakeFee) / 10000;
        }
        
        stakes[msg.sender].amount -= amount;
        totalStaked -= amount;
        stakingToken.safeTransfer(msg.sender, amount - fee);
        if (fee > 0) stakingToken.safeTransfer(owner(), fee); // 手续费归项目方
        
        emit Unstaked(msg.sender, amount, fee);
    }
    
    function claimReward() external nonReentrant updateReward(msg.sender) {
        uint256 reward = stakes[msg.sender].rewards;
        require(reward > 0, "No reward");
        stakes[msg.sender].rewards = 0;
        rewardToken.safeTransfer(msg.sender, reward);
        emit RewardPaid(msg.sender, reward);
    }
    
    function setRewardRate(uint256 _rate) external onlyOwner updateReward(address(0)) {
        rewardRate = _rate;
    }
    
    function setLockPeriod(uint256 _period) external onlyOwner {
        lockPeriod = _period;
    }
}
```

#### 2.1.3 ERC-4337账户抽象（Account Abstraction）

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title 简单账户抽象钱包 — 支持社交恢复/多签/无Gas交易
contract SimpleAccount {
    using ECDSA for bytes32;
    
    address public owner;
    address[] public guardians;
    uint256 public guardianThreshold;
    uint256 public recoveryDelay = 7 days;
    
    struct RecoveryRequest {
        address newOwner;
        uint256 requestTime;
        uint256 approvals;
    }
    RecoveryRequest public pendingRecovery;
    mapping(address => bool) public hasApproved;
    
    event Executed(address indexed to, uint256 value, bytes data);
    event RecoveryRequested(address indexed newOwner, uint256 requestTime);
    event RecoveryExecuted(address indexed newOwner);
    
    constructor(address _owner, address[] memory _guardians, uint256 _threshold) {
        owner = _owner;
        guardians = _guardians;
        guardianThreshold = _threshold;
    }
    
    /// @notice 验证UserOperation签名（ERC-4337入口点调用）
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData) {
        // 验证签名
        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        address signer = hash.recover(userOp.signature);
        require(signer == owner, "Invalid signature");
        
        // 支付缺失的Gas
        if (missingAccountFunds > 0) {
            (bool success, ) = payable(msg.sender).call{value: missingAccountFunds}("");
            require(success, "Payment failed");
        }
        
        return 0; // SIG_VALIDATION_SUCCESS
    }
    
    /// @notice 执行任意操作
    function execute(address to, uint256 value, bytes calldata data) 
        external returns (bytes memory result) {
        require(msg.sender == owner || msg.sender == address(this), "Unauthorized");
        (bool success, bytes memory returnData) = to.call{value: value}(data);
        require(success, "Execution failed");
        emit Executed(to, value, data);
        return returnData;
    }
    
    /// @notice 社交恢复：请求更换Owner
    function requestRecovery(address newOwner) external {
        require(_isGuardian(msg.sender), "Not guardian");
        if (pendingRecovery.newOwner != newOwner) {
            pendingRecovery = RecoveryRequest(newOwner, block.timestamp, 0);
            emit RecoveryRequested(newOwner, block.timestamp);
        }
        require(!hasApproved[msg.sender], "Already approved");
        hasApproved[msg.sender] = true;
        pendingRecovery.approvals++;
        
        if (pendingRecovery.approvals >= guardianThreshold) {
            require(block.timestamp >= pendingRecovery.requestTime + recoveryDelay, 
                "Recovery delay");
            owner = pendingRecovery.newOwner;
            delete pendingRecovery;
            emit RecoveryExecuted(newOwner);
        }
    }
    
    function _isGuardian(address account) internal view returns (bool) {
        for (uint256 i = 0; i < guardians.length; i++) {
            if (guardians[i] == account) return true;
        }
        return false;
    }
    
    receive() external payable {}
}
```

### 2.2 Solana智能合约开发

#### 2.2.1 Anchor Program结构

```rust
use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer, MintTo};

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod custom_token {
    use super::*;

    /// 初始化代币Mint和元数据
    pub fn initialize_token(
        ctx: Context<InitializeToken>,
        name: String,
        symbol: String,
        uri: String,
        decimals: u8,
        initial_supply: u64,
    ) -> Result<()> {
        let token_data = &mut ctx.accounts.token_data;
        token_data.authority = ctx.accounts.authority.key();
        token_data.name = name;
        token_data.symbol = symbol;
        token_data.uri = uri;
        token_data.total_supply = 0;
        token_data.bump = ctx.bumps.token_data;

        // 铸造初始供应量
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            MintTo {
                mint: ctx.accounts.mint.to_account_info(),
                to: ctx.accounts.token_account.to_account_info(),
                authority: ctx.accounts.authority.to_account_info(),
            },
        );
        token::mint_to(cpi_ctx, initial_supply)?;

        token_data.total_supply = initial_supply;
        Ok(())
    }

    /// 转账（带自定义逻辑）
    pub fn transfer_with_fee(
        ctx: Context<TransferWithFee>,
        amount: u64,
        fee_bps: u16, // 基点，如 100 = 1%
    ) -> Result<()> {
        require!(fee_bps <= 1000, ErrorCode::FeeTooHigh); // 最大10%

        let fee_amount = (amount as u128 * fee_bps as u128 / 10000) as u64;
        let transfer_amount = amount - fee_amount;

        // 转手续费
        if fee_amount > 0 {
            let cpi_ctx = CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.from.to_account_info(),
                    to: ctx.accounts.fee_vault.to_account_info(),
                    authority: ctx.accounts.authority.to_account_info(),
                },
            );
            token::transfer(cpi_ctx, fee_amount)?;
        }

        // 转剩余
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.from.to_account_info(),
                to: ctx.accounts.to.to_account_info(),
                authority: ctx.accounts.authority.to_account_info(),
            },
        );
        token::transfer(cpi_ctx, transfer_amount)?;

        emit!(TransferEvent {
            from: ctx.accounts.authority.key(),
            to: ctx.accounts.to.key(),
            amount: transfer_amount,
            fee: fee_amount,
        });

        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(name: String, symbol: String, uri: String, decimals: u8, initial_supply: u64)]
pub struct InitializeToken<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    /// Mint账户（PDA）
    #[account(
        init,
        payer = authority,
        mint::decimals = decimals,
        mint::authority = authority.key(),
    )]
    pub mint: Account<'info, Mint>,

    /// 代币元数据存储
    #[account(
        init,
        payer = authority,
        space = 8 + TokenData::LEN,
        seeds = [b"token_data", mint.key().as_ref()],
        bump,
    )]
    pub token_data: Account<'info, TokenData>,

    /// 接收初始供应的代币账户
    #[account(
        init,
        payer = authority,
        token::mint = mint,
        token::authority = authority,
    )]
    pub token_account: Account<'info, TokenAccount>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct TransferWithFee<'info> {
    pub authority: Signer<'info>,
    #[account(mut)]
    pub from: Account<'info, TokenAccount>,
    #[account(mut)]
    pub to: Account<'info, TokenAccount>,
    #[account(mut)]
    pub fee_vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[account]
pub struct TokenData {
    pub authority: Pubkey,       // 32
    pub name: String,            // 4 + len
    pub symbol: String,          // 4 + len
    pub uri: String,             // 4 + len
    pub total_supply: u64,       // 8
    pub bump: u8,                // 1
}

impl TokenData {
    pub const LEN: usize = 32 + (4 + 64) + (4 + 16) + (4 + 200) + 8 + 1 + 64;
}

#[event]
pub struct TransferEvent {
    pub from: Pubkey,
    pub to: Pubkey,
    pub amount: u64,
    pub fee: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Fee cannot exceed 10%")]
    FeeTooHigh,
}
```

#### 2.2.2 Solana DEX集成（Raydium/Jupiter）

```rust
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    transaction::Transaction,
};
use std::str::FromStr;

// === Raydium AMM Swap ===
pub struct RaydiumSwap {
    pub amm_program: Pubkey,  // Raydium AMM v4
    pub amm_pool: Pubkey,
    pub amm_authority: Pubkey,
    pub user_source: Pubkey,
    pub user_destination: Pubkey,
    pub pool_source: Pubkey,
    pub pool_destination: Pubkey,
    pub serum_open_orders: Pubkey,
    pub serum_market: Pubkey,
    pub serum_program: Pubkey,
}

impl RaydiumSwap {
    pub fn new() -> Self {
        Self {
            amm_program: Pubkey::from_str("675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8").unwrap(),
            amm_pool: Pubkey::default(),
            amm_authority: Pubkey::default(),
            user_source: Pubkey::default(),
            user_destination: Pubkey::default(),
            pool_source: Pubkey::default(),
            pool_destination: Pubkey::default(),
            serum_open_orders: Pubkey::default(),
            serum_market: Pubkey::default(),
            serum_program: Pubkey::from_str("9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin").unwrap(),
        }
    }

    pub fn build_swap_instruction(
        &self,
        amount_in: u64,
        minimum_amount_out: u64,
    ) -> Instruction {
        let data = raydium_amm::instruction::Swap {
            amount_in,
            minimum_amount_out,
        };
        
        Instruction {
            program_id: self.amm_program,
            accounts: vec![
                AccountMeta::new(self.amm_pool, false),
                AccountMeta::new_readonly(self.amm_authority, false),
                AccountMeta::new(self.user_source, false),
                AccountMeta::new(self.pool_source, false),
                AccountMeta::new(self.pool_destination, false),
                AccountMeta::new(self.user_destination, false),
                AccountMeta::new(self.serum_market, false),
                AccountMeta::new(self.serum_open_orders, false),
                // ... 更多必需账户
            ],
            data: data.data(),
        }
    }
}

// === Jupiter Aggregator Quote & Swap ===
pub async fn jupiter_quote(
    input_mint: &str,
    output_mint: &str,
    amount: u64,
    slippage_bps: u16,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let url = format!(
        "https://quote-api.jup.ag/v6/quote?inputMint={}&outputMint={}&amount={}&slippageBps={}",
        input_mint, output_mint, amount, slippage_bps
    );
    let response = reqwest::get(&url).await?;
    let quote = response.json::<serde_json::Value>().await?;
    Ok(quote)
}
```

---

## 3. DApp/DeFi项目定制 & Web3官网 & 白皮书

### 3.1 DApp前端架构

**技术栈选择**：

| 层级 | 技术选择 | 说明 |
|------|----------|------|
| 框架 | Next.js 14+ (App Router) | SSR/SSG/ISR + 服务端组件 |
| 状态管理 | Zustand / Jotai | 轻量级，适合Web3场景 |
| Web3 Provider | wagmi v2 + viem v2 | 多钱包+EIP-6963+类型安全 |
| 钱包连接 | Web3Modal / RainbowKit / AppKit | 社交登录+多链 |
| UI组件 | TailwindCSS + shadcn/ui + Radix | 高度可定制+可访问性 |
| 数据索引 | The Graph / Ponder / Envio | 链上数据索引 |
| API服务 | Alchemy / QuickNode / Helius / Triton | 高性能RPC |
| 动画 | Framer Motion / GSAP | Web3页面动效 |

**DApp项目结构模板**：

```
web3-dapp/
├── app/
│   ├── layout.tsx              # 根布局（Provider包装）
│   ├── page.tsx                # 首页
│   ├── swap/page.tsx           # 兑换页
│   ├── pool/page.tsx           # 流动性页
│   ├── stake/page.tsx          # 质押页
│   └── api/                    # API路由
│       └── quote/route.ts      # 报价接口
├── components/
│   ├── web3/
│   │   ├── providers.tsx       # Web3 Provider
│   │   ├── wallet-button.tsx   # 连接钱包按钮
│   │   ├── swap-form.tsx       # 兑换表单
│   │   ├── token-selector.tsx  # 代币选择器
│   │   └── transaction-toast.tsx
│   ├── ui/                     # shadcn/ui组件
│   └── layout/
│       ├── header.tsx
│       └── footer.tsx
├── lib/
│   ├── config.ts               # 合约地址/RPC/链配置
│   ├── abi/                    # 合约ABI
│   ├── hooks/                  # 自定义hooks
│   │   ├── use-token-balance.ts
│   │   ├── use-swap.ts
│   │   └── use-approve.ts
│   └── utils/
│       ├── format.ts           # 格式化工具
│       └── explorer.ts         # 区块浏览器链接
├── public/
│   ├── images/
│   └── fonts/
└── contract/                   # 合约源码
    ├── src/
    ├── script/
    └── test/
```

**Web3 Provider配置（Next.js 14 App Router）**：

```tsx
// components/web3/providers.tsx
'use client';

import { WagmiProvider, createConfig, http } from 'wagmi';
import { mainnet, bsc, polygon, arbitrum, base, optimism } from 'wagmi/chains';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { createAppKit } from '@reown/appkit/react';
import { WagmiAdapter } from '@reown/appkit-adapter-wagmi';

const projectId = process.env.NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID!;

const wagmiAdapter = new WagmiAdapter({
  networks: [mainnet, bsc, polygon, arbitrum, base, optimism],
  projectId,
  ssr: true,
});

createAppKit({
  adapters: [wagmiAdapter],
  projectId,
  networks: [mainnet, bsc],
  metadata: {
    name: 'My Web3 DApp',
    description: 'Next-Gen DeFi Platform',
    url: 'https://myapp.com',
    icons: ['https://myapp.com/icon.png'],
  },
  features: {
    analytics: true,
    email: true,
    socials: ['google', 'x', 'github', 'discord'],
  },
});

const queryClient = new QueryClient();

export function Web3Providers({ children }: { children: React.ReactNode }) {
  return (
    <WagmiProvider config={wagmiAdapter.wagmiConfig}>
      <QueryClientProvider client={queryClient}>
        {children}
      </QueryClientProvider>
    </WagmiProvider>
  );
}
```

### 3.2 DeFi项目定制方案

| 项目类型 | 核心功能 | 技术栈 | 典型周期 |
|----------|----------|--------|----------|
| DEX(去中心化交易所) | AMM/订单簿/流动性挖矿/限价单 | Solidity + React + The Graph | 4-8周 |
| Lending(借贷协议) | 存款/借款/清算/利率模型 | Solidity(Compound/Aave fork) | 6-10周 |
| Yield Aggregator(收益聚合器) | 自动复投/策略路由/保险库 | Solidity(Yearn fork) + React | 4-8周 |
| Launchpad(发射台) | IDO/IFO/白名单/分配 | Solidity + React + Merkle | 3-6周 |
| NFT Marketplace | 铸造/交易/拍卖/版税 | Solidity + React + IPFS | 4-8周 |
| GameFi | 游戏逻辑/资产/NFT/经济模型 | Solidity + Unity/React | 8-16周 |
| RWA(实物资产代币化) | 合规/预言机/资产锚定 | Solidity + Chainlink | 6-12周 |
| SocialFi | 社交图谱/代币化/内容激励 | Lens Protocol + React | 4-8周 |

### 3.3 Web3官网设计

**官网功能模块**：

```
Web3官网架构
├── Hero Section
│   ├── 动态3D背景（Three.js / Spline）
│   ├── 核心Slogan + CTA按钮
│   └── 实时链上数据展示（TVL/用户数/交易量）
├── 项目介绍
│   ├── 问题陈述 & 解决方案
│   ├── Value Proposition
│   └── 动画演示产品流程
├── Tokenomics
│   ├── 代币分配饼图（D3.js/Recharts）
│   ├── 释放时间轴
│   └── 机构/社区分发比例
├── Roadmap
│   ├── 里程碑时间线
│   ├── 进度可视化
│   └── 已完成/进行中/计划中
├── Team
│   ├── 核心成员介绍
│   ├── 顾问/投资人
│   └── 社交媒体链接
├── Partners & Backers
│   ├── 投资机构Logo墙
│   ├── 生态合作伙伴
│   └── 审计机构
├── FAQ
│   ├── 项目常见问题
│   └── 折叠面板交互
├── Community
│   ├── Discord/Twitter/Telegram入口
│   ├── 实时社区数据
│   └── 新闻/博客模块
└── Footer
    ├── 社交链接
    ├── 文档链接
    └── 法律声明
```

**SEO优化策略**：

| 维度 | 策略 | 技术方案 |
|------|------|---------|
| 服务端渲染 | Next.js SSR/ISR | 搜索引擎可索引 |
| 元数据 | Open Graph / Twitter Card | 社交分享预览优化 |
| 结构化数据 | JSON-LD Schema.org | 富文本搜索结果 |
| 多语言 | i18n (next-intl) | 中/英/日/韩/西 |
| 性能 | Lighthouse 90+ | 图片优化/CDN/代码分割 |
| Sitemap | 自动生成 | 搜索引擎发现 |

### 3.4 白皮书服务

**白皮书类型**：

| 类型 | 页数 | 内容 | 适用场景 |
|------|------|------|----------|
| 技术白皮书 | 30-60页 | 协议架构/共识机制/密码学/经济模型 | 技术导向项目 |
| 商业白皮书 | 20-40页 | 市场分析/商业模式/竞争优势/代币经济 | 面向投资者 |
| Litepaper | 8-15页 | 项目概述/核心卖点/路线图 | 社区传播 |
| Pitch Deck | 15-25页 | 投资亮点/市场/团队/财务预测 | VC融资 |
| One-Pager | 1页 | 一句话总结+核心数据 | 快速传播 |

**Tokenomics建模**：

```
代币经济模型设计
├── 代币基础参数
│   ├── 总供应量 / 初始流通量
│   ├── 代币类型（Utility/Governance/Security）
│   └── 通胀/通缩机制
├── 分配方案
│   ├── 团队 & 顾问 (10-20%)
│   ├── 投资人 (10-25%)
│   ├── 生态基金 (15-30%)
│   ├── 社区激励 (20-40%)
│   ├── 流动性 (5-10%)
│   └── 公募/IDO (5-20%)
├── 释放计划
│   ├── Cliff期（悬崖期）
│   ├── 线性释放周期
│   └── 释放曲线可视化
├── 价值捕获
│   ├── 手续费回购 & 销毁
│   ├── 质押收益
│   ├── 治理权
│   └── 协议收入分成
└── 模拟分析
    ├── 流通量预测
    ├── 价格敏感度分析
    ├── 极端场景压力测试
    └── veTokenomics模型
```

---

## 4. 合约审计 & Bitget上币 & KOL资源 & 海外站台

### 4.1 合约审计服务

**审计流程**：

```
第一阶段：自动化审计
├── Slither — 静态分析（EVM）
├── Mythril — 符号执行
├── Aderyn — Rust静态分析（Foundry）
├── Echidna — 模糊测试
├── Certora — 形式化验证
├── 4naly3er — Gas优化
└── Solhint — 代码规范

第二阶段：人工审计
├── 业务逻辑审查
├── 访问控制审查
├── 经济模型攻击模拟
│   ├── 闪电贷攻击
│   ├── 价格操纵
│   ├── 重入攻击
│   ├── 抢先交易(MEV)
│   └── 治理攻击
├── 跨合约调用链分析
├── 升级代理安全性
└── 第三方依赖审查

第三阶段：外部审计对接
├── CertiK (审计费 $20K-$500K)
├── SlowMist/慢雾 (审计费 $10K-$100K)
├── Trail of Bits (审计费 $50K-$500K)
├── PeckShield/派盾 (审计费 $10K-$80K)
├── Quantstamp (审计费 $20K-$200K)
├── Hacken (审计费 $5K-$50K)
└── Beosin (审计费 $5K-$50K)

第四阶段：报告与修复
├── 漏洞分级（Critical/High/Medium/Low/Info）
├── PoC（漏洞证明）
├── 修复建议 + 代码Patch
├── 复测验证
└── 最终审计报告
```

**常见漏洞检查清单**：

| 漏洞类别 | SWC ID | 严重性 | 检测方法 |
|----------|--------|--------|---------|
| 重入攻击 | SWC-107 | Critical | Slither reentrancy-eth |
| 整数溢出/下溢 | SWC-101 | High | Solidity 0.8+ 内置 |
| 未检查返回值 | SWC-104 | Medium | call返回值检查 |
| 访问控制缺陷 | SWC-105 | Critical | Ownable检查 |
| 时间戳依赖 | SWC-116 | Medium | block.timestamp |
| 前端运行 | SWC-114 | Medium | commit-reveal方案 |
| 拒绝服务 | SWC-113 | High | 循环Gas消耗 |
| 未初始化代理 | SWC-112 | Critical | OpenZeppelin初始化器 |
| 签名重放 | SWC-121 | High | nonce/chainId |
| 预言机操控 | SWC-120 | Critical | 多源预言机 |

### 4.2 Bitget代币上架服务

**上架流程全景**：

```
Bitget代币上架全流程
│
├── 第一阶段：项目评估（1-2周）
│   ├── 项目质量评估
│   │   ├── 技术创新性
│   │   ├── 团队背景
│   │   ├── 社区活跃度
│   │   └── 代币经济模型
│   ├── 合规审查
│   │   ├── 法律意见书
│   │   ├── KYC/AML合规
│   │   ├── 牌照/注册地
│   │   └── 证券属性判定
│   └── 上架可行性报告
│
├── 第二阶段：材料准备（2-4周）
│   ├── 项目介绍文档(中/英)
│   ├── 技术白皮书
│   ├── 代币审计报告
│   ├── 法律意见书
│   ├── 团队KYC材料
│   ├── 社区数据报告
│   ├── 流动性计划
│   └── 做市商方案
│
├── 第三阶段：商务对接（2-4周）
│   ├── 提交上架申请
│   ├── Bitget上币组初审
│   ├── 技术对接（代币合约审计）
│   ├── 商务谈判（上币费/做市）
│   ├── 内部投票/评审
│   └── 上架确认函
│
├── 第四阶段：技术上线（1-2周）
│   ├── 合约部署 & 验证
│   ├── 充提测试
│   ├── 交易对配置
│   ├── 流动性注入
│   └── 压力测试
│
└── 第五阶段：市场推广（同步进行）
    ├── 官方公告配合
    ├── KOL矩阵推广
    ├── 社区AMA
    ├── Trading Campaign
    └── 持续性市场支持
```

**主流CEX上币要求对比**：

| 交易所 | 上币费 | 审计要求 | 做市要求 | 处理周期 | 难度 |
|--------|--------|----------|----------|----------|------|
| Binance | 无公开费用 | 顶级审计所 | 要求 | 3-6月 | ★★★★★ |
| Coinbase | 无公开费用 | 法律合规优先 | 不强制 | 2-4月 | ★★★★★ |
| OKX | 中等 | 审计报告 | 要求 | 1-3月 | ★★★★ |
| Bybit | 中等 | 审计报告 | 要求 | 1-3月 | ★★★★ |
| **Bitget** | 中低 | 审计报告 | 要求 | 1-2月 | ★★★ |
| Gate.io | 低 | 基础审计 | 可选 | 2-4周 | ★★ |
| MEXC | 低 | 基础审计 | 可选 | 1-2周 | ★ |
| Kucoin | 中低 | 审计报告 | 推荐 | 1-2月 | ★★★ |
| HTX(火币) | 中等 | 审计报告 | 要求 | 1-3月 | ★★★ |
| BitMart | 低 | 基础审计 | 可选 | 1-2周 | ★ |

### 4.3 KOL资源矩阵

**KOL资源分类**：

| KOL类型 | 平台 | 粉丝范围 | 合作形式 | 适用场景 |
|---------|------|----------|----------|----------|
| 头部KOL | Twitter/YouTube | 100K-1M+ | 视频/推文/AMA | 品牌曝光/信任背书 |
| 腰部KOL | Twitter/YouTube | 10K-100K | 推文/视频/教程 | 精准传播/社区转化 |
| 尾部KOL | Twitter/Telegram | 1K-10K | 批量推文/转发 | 社区热度/刷屏 |
| YouTube博主 | YouTube | 50K-500K | 项目评测/教程 | 深度教育/长尾流量 |
| TikTok创作者 | TikTok | 100K-1M+ | 短视频/挑战赛 | 年轻用户/病毒传播 |
| TG Call频道 | Telegram | 5K-100K | Call channel/置顶 | 短期涨幅/交易热度 |
| 中文KOL | 微信/微博/B站 | 10K-500K | 文章/视频/直播 | 华人市场 |
| 英文KOL | Twitter/YouTube | 50K-1M+ | 推文/视频/AMA | 全球市场 |
| 日韩KOL | Twitter/Line/YouTube | 20K-300K | 推文/视频 | 日韩市场 |
| 东南亚KOL | Twitter/TikTok | 20K-200K | 推文/短视频 | 东南亚市场 |

**KOL合作流程**：

```
1. 需求分析
   ├── 目标市场（华语/英语/全球/特定区域）
   ├── 预算范围
   ├── 推广目标（曝光/社区增长/交易量/上币预期）
   └── 时间窗口

2. KOL匹配
   ├── 粉丝画像匹配（Web3用户/交易者/开发者）
   ├── 历史合作效果回溯
   ├── 内容风格匹配
   └── 报价谈判

3. 内容策划
   ├── Brief脚本（核心信息/卖点/CTA）
   ├── 视觉素材（Banner/Logo/截图）
   ├── 内容审核（合规/无误导）
   └── 发布时间协调

4. 效果追踪
   ├── 曝光量/互动量
   ├── 链接点击量
   ├── 社区增长数据
   ├── 代币交易量变化
   └── ROI分析报告
```

### 4.4 海外老外站台服务

**海外站台资源类型**：

| 资源类型 | 具体形式 | 效果 | 适用阶段 |
|----------|----------|------|----------|
| 海外顾问 | 项目顾问/Advisor | 信任背书 | 项目早期 |
| 海外团队 | 联合创始人/CTO/CMO | 团队国际化 | 项目启动 |
| 海外VC背书 | 投资机构Logo | 融资可信度 | 融资阶段 |
| 海外KOL站台 | 视频/推文推荐 | 社区信任 | 推广阶段 |
| 海外社区运营 | Discord/Telegram Mod | 社区活跃度 | 持续运营 |
| AMA主持 | 英文AMA/Twitter Space | 社区互动 | 节点推广 |
| 海外PR | CoinTelegraph/CoinDesk/Decrypt | 媒体曝光 | 品牌建设 |
| 海外活动 | 线下Meetup/黑客松 | 社区建设 | 品牌深化 |
| 海外认证 | CertiK/SlowMist审计 | 安全信任 | 上线前 |
| 海外法律 | 法律意见书/合规架构 | 合规保障 | 全周期 |

**海外社区运营方案**：

```
Discord社区运营
├── 频道架构
│   ├── #welcome — 欢迎+规则+验证
│   ├── #announcements — 官方公告
│   ├── #general-chat — 社区聊天
│   ├── #price-talk — 价格讨论
│   ├── #development — 技术讨论
│   ├── #support — 客服支持
│   ├── #memes — 社区文化
│   └── #multi-lang — 多语言分区
├── 角色体系
│   ├── OG — 早期贡献者
│   ├── Mod — 社区管理员
│   ├── Ambassador — 大使
│   └── Contributor — 贡献者
├── 激励机制
│   ├── 活跃度积分
│   ├── 角色升级
│   ├── 代币空投
│   └── 独家权益
└── 活动运营
    ├── 每周AMA
    ├── 社区竞赛
    ├── Meme大赛
    └── Bug Bounty
```

**海外PR发稿渠道**：

| 媒体 | 受众 | 影响力 | 费用 |
|------|------|--------|------|
| CoinTelegraph | 全球Web3用户 | ★★★★★ | $$$

| CoinDesk | 全球Web3用户 | ★★★★★ | $$$

| Decrypt | 全球Web3用户 | ★★★★ | $$

| The Block | 机构/专业用户 | ★★★★ | $$

| Cointelegraph中文 | 华语用户 | ★★★★ | $$

| Bitcoin.com | 全球比特币用户 | ★★★★ | $$

| CryptoSlate | 全球Web3用户 | ★★★ | $

| BeInCrypto | 全球Web3用户 | ★★★ | $

| U.Today | 全球Web3用户 | ★★★ | $

| AMBCrypto | 全球Web3用户 | ★★★ | $

| Yahoo Finance | 传统金融用户 | ★★★★★ | $$$

| Bloomberg | 机构用户 | ★★★★★ | $$$$

| Business Insider | 商业用户 | ★★★★ | $$$

---

## 5. 项目交付流程

### 5.1 全流程项目管理

```
阶段一：需求分析（Week 1）
├── 项目定位 & 竞品分析
├── 技术选型 & 架构设计
├── 功能清单 & 优先级
└── 报价 & 排期确认

阶段二：设计阶段（Week 1-2）
├── UI/UX设计稿
├── 智能合约架构设计
├── 代币经济模型设计
├── 白皮书大纲
└── 官网原型

阶段三：开发阶段（Week 2-8）
├── 智能合约开发 & 测试
├── DApp前端开发
├── 官网开发
├── 白皮书撰写
└── 集成测试

阶段四：审计 & 优化（Week 6-10）
├── 合约内部审计
├── 外部审计对接
├── 前端安全审查
├── 性能优化
└── Gas优化

阶段五：上线 & 推广（Week 8-12）
├── 主网部署
├── CEX上币申请
├── KOL推广启动
├── 社区建设
└── 海外PR发稿
```

### 5.2 交付物清单

| 交付物 | 说明 | 格式 |
|--------|------|------|
| 智能合约源码 | 含注释/测试/部署脚本 | Solidity/Rust |
| 合约审计报告 | 内部+外部审计 | PDF |
| 合约部署验证 | 主网已部署+验证 | 区块浏览器链接 |
| DApp前端 | 响应式/多钱包/多链 | Next.js源码+部署 |
| Web3官网 | SEO优化/多语言 | Next.js源码+部署 |
| 白皮书 | 技术/商业/Litepaper | PDF + 源文件 |
| 代币经济模型 | 分配/释放/模拟 | Excel + 可视化 |
| Pitch Deck | 融资PPT | PDF/PPTX |
| 上币材料包 | 全套申请材料 | 文档包 |
| KOL推广报告 | 效果数据+ROI | 报告 |
| 技术文档 | API/合约/部署 | GitBook/Markdown |

---

## 6. 常见问题与解决方案

### 6.1 合约开发常见坑

| 问题 | 原因 | 解决方案 |
|------|------|---------|
| 代理合约存储冲突 | 实现合约和代理合约的存储slot冲突 | 使用OpenZeppelin Upgradeable/间隙存储 |
| 闪电贷攻击 | 价格预言机可被操控 | 使用TWAP/Chainlink预言机 |
| 重入攻击 | 外部调用在状态更新前 | CEI模式(Check-Effects-Interactions)+ReentrancyGuard |
| Sandwich攻击 | 交易在mempool可见 | 滑点保护+隐私交易 |
| 签名重放 | 缺少nonce/chainId | EIP-712结构化签名 |
| CREATE2地址碰撞 | 盐值可预测 | 加随机盐+msg.sender |
| 前端运行 | 交易提交到公开mempool | Flashbots/MEV-Boost |
| 跨链桥漏洞 | 跨链消息验证不严 | 多重验证+时间锁 |

### 6.2 上币常见拒因

| 拒因 | 说明 | 预防措施 |
|------|------|----------|
| 项目质量不足 | 技术/产品/团队不达标 | 提前评估+完善项目 |
| 合规问题 | 法律/监管风险 | 法律意见书+合规架构 |
| 社区不足 | 社区活跃度低 | 提前建设社区(3月+) |
| 流动性不足 | 链上深度不够 | 做市商方案+流动性计划 |
| 安全事件 | 合约有漏洞/被攻击 | 提前审计+修复 |
| 代币分配不当 | 团队/投资人占比过高 | 合理分配+锁仓 |
| 缺乏创新 | 跟风项目 | 差异化定位+技术创新 |

---

## 7. 工具链与资源

### 7.1 开发工具

| 工具 | 用途 | 链接 |
|------|------|------|
| Hardhat | EVM开发框架 | hardhat.org |
| Foundry | EVM开发框架(Rust) | getfoundry.sh |
| OpenZeppelin | 合约安全库 | openzeppelin.com/contracts |
| Anchor | Solana开发框架 | anchor-lang.com |
| wagmi | React Hooks | wagmi.sh |
| viem | TypeScript ETH库 | viem.sh |
| Web3Modal/AppKit | 钱包连接 | reown.com |
| The Graph | 链上数据索引 | thegraph.com |
| Tenderly | 合约监控/调试 | tenderly.co |
| Alchemy | RPC节点 | alchemy.com |
| Helius | Solana RPC | helius.dev |
| Thirdweb | 全栈Web3平台 | thirdweb.com |

### 7.2 审计工具

| 工具 | 用途 | 平台 |
|------|------|------|
| Slither | 静态分析 | EVM |
| Mythril | 符号执行 | EVM |
| Echidna | 模糊测试 | EVM |
| Certora | 形式化验证 | EVM |
| Aderyn | Rust静态分析 | Foundry |
| 4naly3er | Gas优化 | Solidity |
| Solhint | 代码规范 | Solidity |
| Soteria | Solana审计 | Solana |

---

> **免责声明**：本技能为服务能力展示，所有服务均基于客户需求定制。代币上架、KOL推广等涉及市场行为，不保证具体效果。合约审计建议多轮+外部审计所双重验证。投资有风险，开发需谨慎。

---

## 8. 2026 深度强化：Web3 最新生态与商业化全栈服务

> 本节覆盖 2026 年 Web3 生态最新技术演进，包括新链生态(Monad/Aptos/Sui/Starknet)、账户抽象全栈、RWA 代币化、DePIN、AI×Web3 融合、MEV 防护、以及全链路商业化交付。

### 8.1 2026 新链生态开发矩阵

```solidity
// 2026 新兴 EVM 链兼容性矩阵
// Monad - 并行 EVM, 10,000+ TPS
// | 特性 | Monad | Ethereum | Polygon zkEVM | Arbitrum | Optimism |
// |------|-------|----------|--------------|----------|----------|
// | TPS | 10,000+ | 15 | 1,000+ | 4,000 | 2,000 |
// | 确定性 | 1秒 | 12秒 | 2秒 | 0.25秒 | 2秒 |
// | Gas费 | <$0.01 | $2-50 | $0.10 | $0.50 | $0.30 |
// | EVM兼容 | 完全 | 原生 | 等价 | 等价 | 等价 |
// | 并行执行 | 是 | 否 | 否 | 否 | 否 |

// Monad 并行 EVM 合约开发示例
pragma solidity ^0.8.24;

contract MonadParallelDEX {
    // Monad 支持并行执行, 需要避免状态冲突
    // 使用细粒度锁或无冲突数据结构
    
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public nonce;
    
    // 并行安全: 每个用户的余额独立, 无状态冲突
    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
        nonce[msg.sender]++;
    }
    
    // 并行安全: 使用用户级锁而非全局锁
    function swap(address tokenIn, address tokenOut, uint256 amountIn) 
        external 
        returns (uint256 amountOut) 
    {
        // Monad 并行执行引擎自动检测状态依赖
        // 不同用户的 swap 可以并行执行
        require(balanceOf[msg.sender] >= amountIn, "Insufficient balance");
        
        balanceOf[msg.sender] -= amountIn;
        // ... swap 逻辑 ...
        nonce[msg.sender]++;
    }
}
```

```move
// Sui Move - 对象中心模型开发
module sui_dex::dex {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    
    /// 流动性池对象 - 独立对象, 支持并行交易
    struct Pool<phantom X, phantom Y> has key {
        id: UID,
        balance_x: Balance<X>,
        balance_y: Balance<Y>,
        lp_supply: Supply<LP<X, Y>>,
        fee_rate: u64,  // 基点, 如 30 = 0.3%
    }
    
    /// LP 代币
    struct LP<phantom X, phantom Y> has drop {}
    
    /// 添加流动性 - 独立对象操作, 可并行
    public fun add_liquidity<X, Y>(
        pool: &mut Pool<X, Y>,
        coin_x: Coin<X>,
        coin_y: Coin<Y>,
        ctx: &mut TxContext
    ): Coin<LP<X, Y>> {
        let amount_x = coin::value(&coin_x);
        let amount_y = coin::value(&coin_y);
        
        // 计算LP份额
        let lp_amount = if (balance::value(&pool.balance_x) == 0) {
            // 首次添加
            (amount_x * amount_y).sqrt()
        } else {
            // 后续添加 - 按比例
            let supply = lp_supply::value(&pool.lp_supply);
            let pool_x = balance::value(&pool.balance_x);
            let pool_y = balance::value(&pool.balance_y);
            
            let amount_x_lp = amount_x * supply / pool_x;
            let amount_y_lp = amount_y * supply / pool_y;
            
            if (amount_x_lp < amount_y_lp) amount_x_lp else amount_y_lp
        };
        
        // 存入代币
        balance::join(&mut pool.balance_x, coin::into_balance(coin_x));
        balance::join(&mut pool.balance_y, coin::into_balance(coin_y));
        
        // 铸造LP代币
        let lp_balance = lp_supply::increase(&mut pool.lp_supply, lp_amount, ctx);
        coin::from_balance(lp_balance, ctx)
    }
    
    /// 交换 - 并行安全(每个Pool是独立对象)
    public fun swap<X, Y>(
        pool: &mut Pool<X, Y>,
        coin_in: Coin<X>,
        min_out: u64,
        ctx: &mut TxContext
    ): Coin<Y> {
        let amount_in = coin::value(&coin_in);
        let reserve_in = balance::value(&pool.balance_x);
        let reserve_out = balance::value(&pool.balance_y);
        
        // 计算手续费
        let fee = amount_in * pool.fee_rate / 10000;
        let amount_in_after_fee = amount_in - fee;
        
        // 恒定乘积公式
        let amount_out = (reserve_out * amount_in_after_fee) / 
                         (reserve_in + amount_in_after_fee);
        
        require!(amount_out >= min_out, "Slippage exceeded");
        
        balance::join(&mut pool.balance_x, coin::into_balance(coin_in));
        
        coin::from_balance(
            balance::split(&mut pool.balance_y, amount_out),
            ctx
        )
    }
}
```

```rust
// Starknet Cairo 1.0 - Validity Rollup 合约开发
// Cairo 是 Starknet 的原生语言, 2026 已更新到 Cairo 2.x

// starknet.cairo - DEX 合约
#[starknet::interface]
trait IDEX<TContractState> {
    fn add_liquidity(ref self: TContractState, amount_a: u256, amount_b: u256) -> u256;
    fn swap(ref self: TContractState, amount_in: u256, min_out: u256) -> u256;
    fn get_price(ref self: TContractState) -> u256;
}

#[starknet::contract]
mod DEX {
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    
    #[storage]
    struct Storage {
        reserve_a: u256,
        reserve_b: u256,
        total_lp: u256,
        lp_balances: LegacyMap::<ContractAddress, u256>,
        fee_rate: u256,  // 基点
    }
    
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        Swap: Swap,
        LiquidityAdded: LiquidityAdded,
    }
    
    #[derive(Drop, starknet::Event)]
    struct Swap {
        sender: ContractAddress,
        amount_in: u256,
        amount_out: u256,
    }
    
    #[derive(Drop, starknet::Event)]
    struct LiquidityAdded {
        provider: ContractAddress,
        amount_a: u256,
        amount_b: u256,
        lp_minted: u256,
    }
    
    #[abi(embed_v0)]
    impl DEXImpl of super::IDEX<ContractState> {
        fn add_liquidity(ref self: ContractState, amount_a: u256, amount_b: u256) -> u256 {
            let reserve_a = self.reserve_a.read();
            let reserve_b = self.reserve_b.read();
            let total_lp = self.total_lp.read();
            
            let lp_amount = if (reserve_a == 0) {
                // 首次添加流动性
                // sqrt(amount_a * amount_b)
                isqrt(amount_a * amount_b)
            } else {
                // 按比例
                let lp_a = amount_a * total_lp / reserve_a;
                let lp_b = amount_b * total_lp / reserve_b;
                if (lp_a < lp_b) { lp_a } else { lp_b }
            };
            
            self.reserve_a.write(reserve_a + amount_a);
            self.reserve_b.write(reserve_b + amount_b);
            self.total_lp.write(total_lp + lp_amount);
            
            // 调用者需要先 transfer 代币到本合约
            lp_amount
        }
        
        fn swap(ref self: ContractState, amount_in: u256, min_out: u256) -> u256 {
            let reserve_in = self.reserve_a.read();
            let reserve_out = self.reserve_b.read();
            let fee_rate = self.fee_rate.read();
            
            // 计算手续费
            let fee = amount_in * fee_rate / 10000;
            let amount_in_after_fee = amount_in - fee;
            
            // x * y = k 公式
            let amount_out = (reserve_out * amount_in_after_fee) / 
                             (reserve_in + amount_in_after_fee);
            
            assert!(amount_out >= min_out, "Slippage exceeded");
            
            self.reserve_a.write(reserve_in + amount_in);
            self.reserve_b.write(reserve_out - amount_out);
            
            self.emit(Event::Swap(Swap {
                sender: starknet::get_caller_address(),
                amount_in: amount_in,
                amount_out: amount_out,
            }));
            
            amount_out
        }
        
        fn get_price(ref self: ContractState) -> u256 {
            let reserve_a = self.reserve_a.read();
            let reserve_b = self.reserve_b.read();
            if (reserve_a == 0) { return 0; }
            (reserve_b * 10_u256.pow(18)) / reserve_a
        }
    }
    
    // 整数平方根 (Cairo 内置)
    fn isqrt(n: u256) -> u256 {
        if (n == 0) { return 0; }
        let mut x = n;
        let mut y = (x + 1) / 2;
        while (y < x) {
            x = y;
            y = (x + n / x) / 2;
        }
        x
    }
}
```

### 8.2 账户抽象 (ERC-4337) 全栈实现

```solidity
// ERC-4337 账户抽象 - 智能钱包合约
pragma solidity ^0.8.24;

import {IAccount} from "@account-abstraction/contracts/interfaces/IAccount.sol";
import {UserOperation} from "@account-abstraction/contracts/interfaces/UserOperation.sol";
import {IPaymaster} from "@account-abstraction/contracts/interfaces/IPaymaster.sol";

// 1. 智能账户合约
contract SmartWallet is IAccount {
    address public owner;
    mapping(address => bool) public guardians;
    uint256 public nonce;
    
    // 社交恢复
    struct RecoveryRequest {
        address newOwner;
        uint256 confirmations;
        uint256 expiry;
    }
    RecoveryRequest public recoveryRequest;
    mapping(address => bool) public recoveryConfirmed;
    uint256 public constant RECOVERY_THRESHOLD = 2;
    uint256 public constant RECOVERY_DELAY = 2 days;
    
    // 限流控制
    struct SpendingLimit {
        uint256 dailyLimit;
        uint256 spentToday;
        uint256 lastResetDay;
    }
    mapping(address => SpendingLimit) public spendingLimits;
    
    event TransactionExecuted(address target, uint256 value, bytes data);
    event RecoveryInitiated(address newOwner, uint256 expiry);
    event RecoveryCompleted(address newOwner);
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    constructor(address _owner, address[] memory _guardians) {
        owner = _owner;
        for (uint256 i = 0; i < _guardians.length; i++) {
            guardians[_guardians[i]] = true;
        }
    }
    
    // ERC-4337 验证函数
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external override returns (uint256 validationData) {
        // 验证签名
        bytes4 sigBytes = bytes4(userOp.signature[0:4]);
        
        if (sigBytes == 0x00000001) {
            // 所有者签名
            require(owner == ECDSA.recover(userOpHash, userOp.signature[4:]), "Invalid owner sig");
        } else if (sigBytes == 0x00000002) {
            // 守护者签名 (社交恢复)
            require(guardians[ECDSA.recover(userOpHash, userOp.signature[4:])], "Invalid guardian sig");
        } else if (sigBytes == 0x00000003) {
            // Session Key 签名 (临时密钥)
            // 验证 Session Key 是否在有效期内且有权限
            _validateSessionKey(userOp);
        }
        
        // 支付 Gas
        if (missingAccountFunds > 0) {
            (bool success,) = payable(msg.sender).call{value: missingAccountFunds}("");
            require(success, "Payment failed");
        }
        
        return 0; // validationData = 0 表示验证通过
    }
    
    // 执行交易
    function execute(
        address dest,
        uint256 value,
        bytes calldata func
    ) external onlyOwner {
        // 检查限流
        _checkSpendingLimit(dest, value);
        
        (bool success, bytes memory result) = dest.call{value: value}(func);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
        emit TransactionExecuted(dest, value, func);
    }
    
    // 批量执行
    function executeBatch(
        address[] calldata dests,
        uint256[] calldata values,
        bytes[] calldata funcs
    ) external onlyOwner {
        require(dests.length == values.length && dests.length == funcs.length, "Array mismatch");
        for (uint256 i = 0; i < dests.length; i++) {
            (bool success,) = dests[i].call{value: values[i]}(funcs[i]);
            require(success, "Batch execution failed");
        }
    }
    
    // 社交恢复 - 发起
    function initiateRecovery(address newOwner) external {
        require(guardians[msg.sender], "Not guardian");
        recoveryRequest = RecoveryRequest({
            newOwner: newOwner,
            confirmations: 1,
            expiry: block.timestamp + RECOVERY_DELAY
        });
        recoveryConfirmed[msg.sender] = true;
        emit RecoveryInitiated(newOwner, recoveryRequest.expiry);
    }
    
    // 社交恢复 - 确认
    function confirmRecovery() external {
        require(guardians[msg.sender], "Not guardian");
        require(!recoveryConfirmed[msg.sender], "Already confirmed");
        require(block.timestamp < recoveryRequest.expiry, "Recovery expired");
        
        recoveryRequest.confirmations++;
        recoveryConfirmed[msg.sender] = true;
        
        if (recoveryRequest.confirmations >= RECOVERY_THRESHOLD) {
            owner = recoveryRequest.newOwner;
            emit RecoveryCompleted(owner);
            delete recoveryRequest;
        }
    }
    
    function _checkSpendingLimit(address token, uint256 amount) internal {
        SpendingLimit storage limit = spendingLimits[token];
        if (limit.dailyLimit == 0) return;
        
        uint256 today = block.timestamp / 1 days;
        if (limit.lastResetDay < today) {
            limit.spentToday = 0;
            limit.lastResetDay = today;
        }
        
        require(limit.spentToday + amount <= limit.dailyLimit, "Daily limit exceeded");
        limit.spentToday += amount;
    }
    
    function _validateSessionKey(UserOperation calldata userOp) internal pure {
        // Session Key 验证逻辑
        // 检查 Session Key 的权限范围和有效期
    }
    
    receive() external payable {}
}

// 2. Paymaster - Gas 赞助合约
contract TokenPaymaster is IPaymaster {
    IERC20 public supportedToken;
    
    constructor(address _token) {
        supportedToken = IERC20(_token);
    }
    
    function validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external override returns (bytes memory context, uint256 validationData) {
        // 解析 Paymaster 数据: [tokenAmount][userSignature]
        require(userOp.paymasterAndData.length > 20, "Invalid paymaster data");
        
        // 验证用户有足够的代币支付 Gas
        address user = userOp.sender;
        uint256 tokenAmount = abi.decode(userOp.paymasterAndData[20:52], (uint256));
        
        require(
            supportedToken.balanceOf(user) >= tokenAmount,
            "Insufficient token balance"
        );
        
        // 返回上下文, postOp 时使用
        context = abi.encode(user, tokenAmount);
        return (context, 0);
    }
    
    function postOp(
        PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost
    ) external override {
        // 从用户账户扣除代币
        (address user, uint256 tokenAmount) = abi.decode(context, (address, uint256));
        
        // 按 Gas 费用折算代币
        uint256 tokenCost = _convertGasToToken(actualGasCost);
        
        supportedToken.transferFrom(user, address(this), tokenCost);
    }
    
    function _convertGasToToken(uint256 gasCost) internal view returns (uint256) {
        // 根据代币价格和 Gas 价格折算
        return gasCost; // 简化
    }
}
```

### 8.3 RWA (Real World Asset) 代币化

```solidity
// RWA 资产代币化合约 - 2026 热门赛道
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

// 房地产代币化
contract RealEstateToken is ERC20, ERC20Burnable, AccessControl, Pausable {
    bytes32 public constant ORACLE_ROLE = keccak256("ORACLE_ROLE");
    bytes32 public constant COMPLIANCE_ROLE = keccak256("COMPLIANCE_ROLE");
    bytes32 public constant ASSET_MANAGER_ROLE = keccak256("ASSET_MANAGER_ROLE");
    
    struct Asset {
        string assetId;           // 链下资产编号
        string assetType;         // "real_estate", "bond", "commodity"
        uint256 totalValue;       // 总估值 (USD, 18 decimals)
        uint256 tokenPrice;       // 每代币价格
        uint256 yieldRate;        // 年化收益率 (基点, 如 500 = 5%)
        uint256 lastValuationTime;// 最后估值时间
        bool isVerified;          // 是否通过验证
    }
    
    struct Investor {
        bool isKYCVerified;       // KYC 状态
        bool isAccredited;        // 合格投资者
        uint256 maxInvestment;    // 最大投资额
        uint256 investedAmount;   // 已投资额
        string jurisdiction;      // 司法管辖区
    }
    
    Asset public asset;
    mapping(address => Investor) public investors;
    mapping(address => bool) public blacklisted;
    
    // 收益分配
    struct YieldDistribution {
        uint256 totalYield;
        uint256 distributedYield;
        uint256 distributionTime;
        bool isComplete;
    }
    YieldDistribution[] public yieldDistributions;
    
    event AssetValued(string assetId, uint256 newValue, uint256 timestamp);
    event YieldDistributed(uint256 totalYield, uint256 perTokenYield);
    event InvestorKYCUpdated(address investor, bool status);
    
    constructor(
        string memory name,
        string memory symbol,
        uint256 totalSupply,
        Asset memory _asset
    ) ERC20(name, symbol) {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(ORACLE_ROLE, msg.sender);
        _setupRole(COMPLIANCE_ROLE, msg.sender);
        _setupRole(ASSET_MANAGER_ROLE, msg.sender);
        
        asset = _asset;
        _mint(msg.sender, totalSupply);
    }
    
    // 合规转移 - 仅 KYC 验证投资者可交易
    function transfer(address to, uint256 amount) public virtual override returns (bool) {
        require(!blacklisted[msg.sender], "Sender blacklisted");
        require(!blacklisted[to], "Recipient blacklisted");
        require(investors[msg.sender].isKYCVerified, "Sender not KYC verified");
        require(investors[to].isKYCVerified, "Recipient not KYC verified");
        
        // 司法管辖区检查
        require(
            _checkJurisdiction(investors[msg.sender].jurisdiction, investors[to].jurisdiction),
            "Jurisdiction mismatch"
        );
        
        return super.transfer(to, amount);
    }
    
    // KYC 验证更新
    function updateKYC(
        address investor,
        bool _isKYCVerified,
        bool _isAccredited,
        uint256 _maxInvestment,
        string calldata _jurisdiction
    ) external onlyRole(COMPLIANCE_ROLE) {
        investors[investor] = Investor({
            isKYCVerified: _isKYCVerified,
            isAccredited: _isAccredited,
            maxInvestment: _maxInvestment,
            investedAmount: investors[investor].investedAmount,
            jurisdiction: _jurisdiction
        });
        emit InvestorKYCUpdated(investor, _isKYCVerified);
    }
    
    // 资产估值更新 (Oracle 调用)
    function updateValuation(uint256 newValue) external onlyRole(ORACLE_ROLE) {
        asset.totalValue = newValue;
        asset.tokenPrice = newValue / totalSupply();
        asset.lastValuationTime = block.timestamp;
        emit AssetValued(asset.assetId, newValue, block.timestamp);
    }
    
    // 收益分配
    function distributeYield(uint256 totalYieldAmount) external onlyRole(ASSET_MANAGER_ROLE) {
        require(asset.isVerified, "Asset not verified");
        
        uint256 perTokenYield = (totalYieldAmount * 1e18) / totalSupply();
        
        yieldDistributions.push(YieldDistribution({
            totalYield: totalYieldAmount,
            distributedYield: 0,
            distributionTime: block.timestamp,
            isComplete: false
        }));
        
        // 按持有比例分配收益
        // 实际实现中需要快照机制
        
        emit YieldDistributed(totalYieldAmount, perTokenYield);
    }
    
    function _checkJurisdiction(string memory from, string memory to) internal pure returns (bool) {
        // 简化: 同一管辖区或双方为白名单管辖区
        return keccak256(bytes(from)) == keccak256(bytes(to)) ||
               keccak256(bytes(from)) == keccak256("SG") ||
               keccak256(bytes(to)) == keccak256("SG");
    }
    
    function pause() external onlyRole(ASSET_MANAGER_ROLE) {
        _pause();
    }
    
    function unpause() external onlyRole(ASSET_MANAGER_ROLE) {
        _unpause();
    }
}
```

### 8.4 DePIN (Decentralized Physical Infrastructure) 开发

```solidity
// DePIN 去中心化物理基础设施网络
pragma solidity ^0.8.24;

// 存储证明 - 类似 Filecoin
contract DePINStorage {
    struct StorageProvider {
        address provider;
        uint256 totalSpace;       // 提供的总空间(bytes)
        uint256 usedSpace;        // 已用空间
        uint256 stakedAmount;     // 质押金额
        uint256 reputation;       // 信誉分
        bool isActive;
        uint256 lastProofTime;    // 最后提交证明时间
    }
    
    struct StorageDeal {
        uint256 dealId;
        address client;
        address provider;
        bytes32 dataHash;         // 存储数据的哈希
        uint256 dataSize;
        uint256 price;            // 每周期价格
        uint256 duration;         // 总周期数
        uint256 startBlock;
        bool isActive;
    }
    
    struct ProofOfSpacetime {
        bytes32 challengeSeed;    // 挑战种子
        bytes32 response;         // 响应哈希
        uint256 sectorId;         // 扇区ID
        uint256 timestamp;
    }
    
    mapping(address => StorageProvider) public providers;
    mapping(uint256 => StorageDeal) public deals;
    mapping(address => ProofOfSpacetime[]) public proofs;
    
    uint256 public nextDealId = 1;
    uint256 public constant MIN_STAKE = 1000 ether;
    uint256 public constant PROOF_PERIOD = 2880; // ~24h (12s blocks)
    uint256 public constant SLASH_RATE = 10; // 10% 质押削减
    
    event ProviderRegistered(address provider, uint256 space, uint256 stake);
    event DealCreated(uint256 dealId, address client, address provider, uint256 duration);
    event ProofSubmitted(address provider, bytes32 response);
    event ProviderSlashed(address provider, uint256 amount, string reason);
    
    // 注册为存储提供者
    function registerProvider(uint256 _totalSpace) external payable {
        require(msg.value >= MIN_STAKE, "Insufficient stake");
        require(!providers[msg.sender].isActive, "Already registered");
        
        providers[msg.sender] = StorageProvider({
            provider: msg.sender,
            totalSpace: _totalSpace,
            usedSpace: 0,
            stakedAmount: msg.value,
            reputation: 100,
            isActive: true,
            lastProofTime: block.timestamp
        });
        
        emit ProviderRegistered(msg.sender, _totalSpace, msg.value);
    }
    
    // 创建存储交易
    function createDeal(
        address provider,
        bytes32 dataHash,
        uint256 dataSize,
        uint256 duration
    ) external payable {
        require(providers[provider].isActive, "Provider not active");
        require(providers[provider].usedSpace + dataSize <= providers[provider].totalSpace, "Insufficient space");
        
        uint256 totalPrice = (msg.value * duration) / 30 days;
        require(msg.value >= totalPrice, "Insufficient payment");
        
        uint256 dealId = nextDealId++;
        deals[dealId] = StorageDeal({
            dealId: dealId,
            client: msg.sender,
            provider: provider,
            dataHash: dataHash,
            dataSize: dataSize,
            price: msg.value / duration,
            duration: duration,
            startBlock: block.number,
            isActive: true
        });
        
        providers[provider].usedSpace += dataSize;
        
        emit DealCreated(dealId, msg.sender, provider, duration);
    }
    
    // 提交时空证明 (Proof of Spacetime)
    function submitProof(
        bytes32 challengeSeed,
        bytes32 response,
        uint256 sectorId
    ) external {
        StorageProvider storage provider = providers[msg.sender];
        require(provider.isActive, "Not active provider");
        
        // 验证挑战种子(由系统生成)
        bytes32 expectedSeed = keccak256(abi.encodePacked(
            msg.sender,
            blockhash(block.number - 1),
            block.number / PROOF_PERIOD
        ));
        require(challengeSeed == expectedSeed, "Invalid challenge seed");
        
        // 存储证明
        proofs[msg.sender].push(ProofOfSpacetime({
            challengeSeed: challengeSeed,
            response: response,
            sectorId: sectorId,
            timestamp: block.timestamp
        }));
        
        provider.lastProofTime = block.timestamp;
        provider.reputation = provider.reputation < 200 ? provider.reputation + 1 : 200;
        
        emit ProofSubmitted(msg.sender, response);
    }
    
    // 惩罚未按时提交证明的提供者
    function slashProvider(address provider) external {
        StorageProvider storage p = providers[provider];
        require(p.isActive, "Provider not active");
        require(
            block.timestamp - p.lastProofTime > PROOF_PERIOD * 12,
            "Proof not overdue"
        );
        
        uint256 slashAmount = (p.stakedAmount * SLASH_RATE) / 100;
        p.stakedAmount -= slashAmount;
        p.reputation = p.reputation > 20 ? p.reputation - 20 : 0;
        
        if (p.stakedAmount < MIN_STAKE / 2) {
            p.isActive = false;
        }
        
        emit ProviderSlashed(provider, slashAmount, "Missed PoSt deadline");
    }
}
```

### 8.5 AI × Web3 融合开发

```solidity
// AI 模型推理市场 - 去中心化 AI 推理
pragma solidity ^0.8.24;

contract AIInferenceMarket {
    // AI 模型注册
    struct AIModel {
        address owner;
        string modelHash;          // IPFS/Arweave 上的模型哈希
        string modelType;          // "text-generation", "image", "embedding"
        uint256 pricePerInference; // 每次推理价格
        uint256 totalInferences;
        uint256 rating;
        uint256 ratingCount;
        bool isActive;
    }
    
    // 推理请求
    struct InferenceRequest {
        uint256 requestId;
        address requester;
        uint256 modelId;
        string inputHash;          // IPFS 上的输入数据哈希
        string outputHash;         // IPFS 上的输出数据哈希
        uint256 price;
        uint256 timestamp;
        bool isCompleted;
        bool isVerified;
    }
    
    // 验证者
    struct Verifier {
        address verifier;
        uint256 stakedAmount;
        uint256 successfulVerifications;
        uint256 failedVerifications;
        bool isActive;
    }
    
    mapping(uint256 => AIModel) public models;
    mapping(uint256 => InferenceRequest) public requests;
    mapping(address => Verifier) public verifiers;
    
    uint256 public nextModelId = 1;
    uint256 public nextRequestId = 1;
    
    // 乐观验证: 推理结果默认有效, 在挑战期内可被验证
    uint256 public constant CHALLENGE_PERIOD = 100; // ~20 minutes
    uint256 public constant VERIFIER_REWARD = 0.01 ether;
    uint256 public constant VERIFIER_STAKE = 1 ether;
    
    event ModelRegistered(uint256 modelId, address owner, string modelType);
    event InferenceRequested(uint256 requestId, uint256 modelId, string inputHash);
    event InferenceCompleted(uint256 requestId, string outputHash);
    event InferenceChallenged(uint256 requestId, address verifier);
    
    // 注册 AI 模型
    function registerModel(
        string calldata modelHash,
        string calldata modelType,
        uint256 pricePerInference
    ) external returns (uint256) {
        uint256 modelId = nextModelId++;
        models[modelId] = AIModel({
            owner: msg.sender,
            modelHash: modelHash,
            modelType: modelType,
            pricePerInference: pricePerInference,
            totalInferences: 0,
            rating: 0,
            ratingCount: 0,
            isActive: true
        });
        
        emit ModelRegistered(modelId, msg.sender, modelType);
        return modelId;
    }
    
    // 请求 AI 推理
    function requestInference(
        uint256 modelId,
        string calldata inputHash
    ) external payable returns (uint256) {
        require(models[modelId].isActive, "Model not active");
        require(msg.value >= models[modelId].pricePerInference, "Insufficient payment");
        
        uint256 requestId = nextRequestId++;
        requests[requestId] = InferenceRequest({
            requestId: requestId,
            requester: msg.sender,
            modelId: modelId,
            inputHash: inputHash,
            outputHash: "",
            price: msg.value,
            timestamp: block.timestamp,
            isCompleted: false,
            isVerified: false
        });
        
        emit InferenceRequested(requestId, modelId, inputHash);
        return requestId;
    }
    
    // 提交推理结果 (模型所有者调用)
    function submitResult(uint256 requestId, string calldata outputHash) external {
        InferenceRequest storage req = requests[requestId];
        require(!req.isCompleted, "Already completed");
        require(models[req.modelId].owner == msg.sender, "Not model owner");
        
        req.outputHash = outputHash;
        req.isCompleted = true;
        
        // 乐观验证: 如果挑战期内无异议, 自动验证
        // 实际实现中需要定时器或外部触发
        
        emit InferenceCompleted(requestId, outputHash);
    }
    
    // 挑战推理结果 (验证者调用)
    function challengeResult(uint256 requestId, string calldata correctOutputHash) external {
        InferenceRequest storage req = requests[requestId];
        require(req.isCompleted, "Not completed");
        require(!req.isVerified, "Already verified");
        require(verifiers[msg.sender].isActive, "Not active verifier");
        require(
            block.timestamp - req.timestamp < CHALLENGE_PERIOD,
            "Challenge period ended"
        );
        
        // 验证者需要提供正确结果
        // 实际验证通过链下计算 + 多签确认
        
        req.isVerified = true;
        verifiers[msg.sender].successfulVerifications++;
        
        // 奖励验证者, 惩罚模型所有者
        payable(msg.sender).transfer(VERIFIER_REWARD);
        
        emit InferenceChallenged(requestId, msg.sender);
    }
    
    // 注册为验证者
    function registerVerifier() external payable {
        require(msg.value >= VERIFIER_STAKE, "Insufficient stake");
        verifiers[msg.sender] = Verifier({
            verifier: msg.sender,
            stakedAmount: msg.value,
            successfulVerifications: 0,
            failedVerifications: 0,
            isActive: true
        });
    }
}
```

### 8.6 MEV 防护与 Flashbots 集成

```python
# MEV 防护与 Flashbots 集成工具
import json
import requests
from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct
import asyncio

class MEVProtection:
    """MEV 防护工具 - 通过 Flashbots Protect 和私有交易池避免三明治攻击"""
    
    def __init__(self, rpc_url: str, private_key: str = None):
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.account = Account.from_key(private_key) if private_key else None
        self.flashbots_protect_url = "https://rpc.flashbots.net/fast"
        self.flashbots_relay_url = "https://relay.flashbots.net"
        
    def send_via_flashbots_protect(self, tx_dict: dict):
        """通过 Flashbots Protect RPC 发送交易(防 MEV)"""
        # Flashbots Protect 会将交易直接发送给构建者
        # 跳过公共 mempool, 避免三明治攻击
        
        w3_protect = Web3(Web3.HTTPProvider(self.flashbots_protect_url))
        
        # 签名交易
        if self.account:
            signed_tx = self.account.sign_transaction(tx_dict)
            tx_hash = w3_protect.eth.send_raw_transaction(signed_tx.rawTransaction)
            return tx_hash.hex()
        
        return None
    
    def send_bundle(self, txs: list, target_block: int):
        """发送交易包到 Flashbots (原子执行)"""
        # 交易包中的所有交易要么全部执行, 要么全部不执行
        # 适合套利/清算等需要原子性的操作
        
        signed_txs = []
        for tx in txs:
            if self.account:
                signed = self.account.sign_transaction(tx)
                signed_txs.append(signed.rawTransaction.hex())
        
        bundle = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_sendBundle",
            "params": [
                {
                    "txs": signed_txs,
                    "blockNumber": hex(target_block),
                }
            ],
        }
        
        # 签名并发送到 Flashbots Relay
        # 需要使用 Flashbots 的签名方案
        
        return bundle
    
    def detect_sandwich_attack(self, target_tx_hash: str):
        """检测交易是否遭受三明治攻击"""
        tx = self.w3.eth.get_transaction(target_tx_hash)
        receipt = self.w3.eth.get_transaction_receipt(target_tx_hash)
        
        block = self.w3.eth.get_block(tx["blockNumber"], full_transactions=True)
        
        # 获取同区块中的所有交易
        block_txs = block["transactions"]
        
        # 查找可能的攻击交易对
        # 三明治攻击: 攻击者在目标交易前买入(前端交易), 在目标交易后卖出(后端交易)
        
        sandwich_findings = {
            "target_tx": target_tx_hash,
            "block_number": tx["blockNumber"],
            "front_run": None,
            "back_run": None,
            "attacker": None,
            "profit": 0,
        }
        
        target_index = None
        for i, btx in enumerate(block_txs):
            if btx["hash"].hex() == target_tx_hash:
                target_index = i
                break
        
        if target_index is None:
            return sandwich_findings
        
        # 检查前一交易(前端)
        if target_index > 0:
            front_tx = block_txs[target_index - 1]
            # 检查是否与目标交易交互同一合约
            if front_tx["to"] and front_tx["to"].lower() == tx["to"].lower():
                # 进一步分析: 是否在目标交易前进行了买入操作
                sandwich_findings["front_run"] = front_tx["hash"].hex()
                sandwich_findings["attacker"] = front_tx["from"]
        
        # 检查后一交易(后端)
        if target_index < len(block_txs) - 1:
            back_tx = block_txs[target_index + 1]
            if back_tx["to"] and back_tx["to"].lower() == tx["to"].lower():
                # 检查是否是同一攻击者
                if back_tx["from"].lower() == sandwich_findings.get("attacker", "").lower():
                    sandwich_findings["back_run"] = back_tx["hash"].hex()
        
        if sandwich_findings["front_run"] and sandwich_findings["back_run"]:
            sandwich_findings["sandwich_detected"] = True
            print(f"[!!!] 检测到三明治攻击!")
            print(f"  前端交易: {sandwich_findings['front_run']}")
            print(f"  目标交易: {target_tx_hash}")
            print(f"  后端交易: {sandwich_findings['back_run']}")
            print(f"  攻击者: {sandwich_findings['attacker']}")
        else:
            sandwich_findings["sandwich_detected"] = False
        
        return sandwich_findings

# DeFi 价格监控与套利
class DeFiArbitrageScanner:
    """跨 DEX 套利扫描器"""
    
    def __init__(self, w3: Web3):
        self.w3 = w3
        self.dex_routers = {
            "Uniswap V3": "0xE592427A0AEce92De3Edee1F18E0157C05861564",
            "SushiSwap": "0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506",
            "PancakeSwap": "0x10ED43C718714eb0d32C05d2b1E5C2D4a1E2aE2e",
        }
        
        # ERC20 ABI (简化)
        self.erc20_abi = [
            {"constant": True, "inputs": [], "name": "decimals", "outputs": [{"type": "uint8"}], "type": "function"},
            {"constant": True, "inputs": [{"name": "account", "type": "address"}], "name": "balanceOf", "outputs": [{"type": "uint256"}], "type": "function"},
        ]
        
        # Uniswap V2 Router ABI (简化)
        self.router_abi = [
            {"inputs": [{"name": "amountIn", "type": "uint256"}, {"name": "path", "type": "address[]"}], "name": "getAmountsOut", "outputs": [{"name": "amounts", "type": "uint256[]"}], "type": "function"},
        ]
    
    def get_price(self, router_address: str, token_in: str, token_out: str, amount_in: int):
        """获取 DEX 上的代币价格"""
        router = self.w3.eth.contract(
            address=Web3.to_checksum_address(router_address),
            abi=self.router_abi
        )
        
        try:
            amounts = router.functions.getAmountsOut(
                amount_in,
                [Web3.to_checksum_address(token_in), Web3.to_checksum_address(token_out)]
            ).call()
            return amounts[-1]
        except Exception as e:
            return 0
    
    def scan_arbitrage(self, token_a: str, token_b: str, amount: int = 10**18):
        """扫描跨 DEX 套利机会"""
        prices = {}
        for dex_name, router in self.dex_routers.items():
            price = self.get_price(router, token_a, token_b, amount)
            if price > 0:
                prices[dex_name] = price
        
        if len(prices) < 2:
            return None
        
        # 找到价差
        max_price_dex = max(prices, key=prices.get)
        min_price_dex = min(prices, key=prices.get)
        max_price = prices[max_price_dex]
        min_price = prices[min_price_dex]
        
        spread = ((max_price - min_price) / min_price) * 100
        
        if spread > 0.5:  # 0.5% 以上价差
            return {
                "buy_dex": min_price_dex,
                "sell_dex": max_price_dex,
                "buy_price": min_price,
                "sell_price": max_price,
                "spread_percent": spread,
                "estimated_profit": max_price - min_price,
                "token_in": token_a,
                "token_out": token_b,
            }
        
        return None
```

### 8.7 2026 Web3 商业化服务全景矩阵

| 服务类型 | 技术栈 | 周期 | 报价范围(USD) | 2026趋势 |
|----------|--------|------|--------------|----------|
| EVM合约开发 | Solidity/Hardhat/Foundry | 2-6周 | $5K-$50K | 并行EVM(Monad) |
| Solana合约开发 | Rust/Anchor | 2-8周 | $8K-$80K | Firedancer客户端 |
| Move合约开发 | Move/Sui Move | 3-8周 | $10K-$60K | Sui/Aptos生态爆发 |
| Cairo合约开发 | Cairo 2.x/Starknet | 3-8周 | $10K-$70K | ZK Rollup主流化 |
| DApp全栈 | Next.js/wagmi/viem | 4-12周 | $15K-$150K | 账户抽象集成 |
| DeFi协议 | Uniswap V4 fork/自定义 | 4-16周 | $20K-$200K | MEV防护标配 |
| RWA代币化 | ERC-3643/ERC-1400 | 4-8周 | $15K-$100K | 合规框架成熟 |
| DePIN开发 | 存储证明/计算证明 | 6-16周 | $30K-$200K | 硬件集成 |
| AI×Web3 | 去中心化推理市场 | 6-12周 | $20K-$150K | AI代理链上化 |
| NFT 2.0 | ERC-6551/动态NFT | 2-6周 | $5K-$50K | 代币绑定账户 |
| 跨链桥 | LayerZero/CCIP | 4-8周 | $15K-$80K | 互操作性标准 |
| 合约审计 | Slither/Mythril/人工 | 1-4周 | $5K-$50K | 形式化验证普及 |
| 代币上币 | Bitget/Gate/MEXC | 4-12周 | $10K-$100K | TON生态热门 |
| KOL推广 | Twitter/YouTube/TG | 按需 | $2K-$50K | 真实粉丝溢价 |
| 海外站台 | AMA/PR/社区 | 按需 | $5K-$30K | 英语母语团队 |

### 8.8 全链路项目交付流程 (2026增强版)

```
Phase 0: 需求分析 (1-2周)
├─ 项目定位(DeFi/GameFi/DePIN/RWA/AI×Web3)
├─ 目标链选择(EVM/Solana/Move/Cairo/多链)
├─ 代币经济模型设计
└─ 合规性评估(证券法/AML/KYC需求)

Phase 1: 架构设计 (1-2周)
├─ 智能合约架构
├─ 前端技术选型(Next.js 14 + wagmi v2 + viem)
├─ 后端服务(Indexer/Subgraph/Pinata)
├─ 账户抽象集成(ERC-4337/Bundler/Paymaster)
├─ 跨链方案(LayerZero v2/CCIP/Wormhole)
└─ 安全架构(MEV防护/多签/时间锁)

Phase 2: 合约开发 (2-8周)
├─ 核心合约实现
├─ 单元测试(覆盖率>95%)
├─ 集成测试
├─ Gas优化
└─ OpenZeppelin审计准备

Phase 3: 前端开发 (2-6周)
├─ 钱包连接(MetaMask/WalletConnect/Coinbase)
├─ 合约交互(hook封装)
├─ 状态管理(Zustand/Jotai)
├─ IPFS集成(元数据/文件存储)
├─ 响应式设计(移动端优先)
└─ SEO优化(Lighthouse 90+)

Phase 4: 安全审计 (1-4周)
├─ 自动化扫描(Slither/Mythril/Aderyn)
├─ 人工审计(逐行审查)
├─ 外部审计对接(CertiK/SlowMist)
├─ 漏洞修复与复审
└─ 审计报告发布

Phase 5: 主网部署 (1-2周)
├─ 测试网全流程验证
├─ 主网合约部署(多签+时间锁)
├─ 前端部署(Vercel/Netlify)
├─ 域名+CDN+SSL
├─ 监控告警(Tenderly/Defender)
└─ 应急响应预案

Phase 6: 运营推广 (持续)
├─ 代币上架(Bitget/Gate/MEXC/Bybit)
├─ KOL矩阵推广
├─ 海外社区运营
├─ AMA/PR/品牌建设
├─ 空投/激励计划
└─ 数据分析与迭代
```

### 8.9 2026 Web3 安全最佳实践

```solidity
// 2026 智能合约安全最佳实践
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

// 1. 重入锁 - 使用最新的瞬态存储(OZ v5 transient)
contract SecureContract is ReentrancyGuard, Pausable, AccessControl {
    // 使用 transient storage 进行重入锁(OZ v5, EIP-1153)
    // 比传统 storage 更省 Gas
    
    // 2. 限流器
    struct RateLimit {
        uint256 window;        // 时间窗口
        uint256 maxAmount;     // 窗口内最大金额
        uint256 currentAmount; // 当前已用金额
        uint256 windowStart;   // 窗口开始时间
    }
    mapping(bytes32 => RateLimit) public rateLimits;
    
    // 3. 紧急暂停
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant TREASURY_ROLE = keccak256("TREASURY_ROLE");
    
    // 4. 升级安全 - UUPS 模式
    // 使用 UUPS 代理而非透明代理, 更省 Gas
    
    // 5. MEV 防护
    // 使用承诺-揭示模式 或 Flashbots Protect
    
    modifier rateLimited(bytes32 action, uint256 amount) {
        RateLimit storage limit = rateLimits[action];
        if (block.timestamp >= limit.windowStart + limit.window) {
            limit.windowStart = block.timestamp;
            limit.currentAmount = 0;
        }
        require(limit.currentAmount + amount <= limit.maxAmount, "Rate limit exceeded");
        limit.currentAmount += amount;
        _;
    }
    
    // 6. 多签时间锁
    struct TimelockRequest {
        address target;
        bytes data;
        uint256 value;
        uint256 executeAfter;
        bool executed;
    }
    mapping(uint256 => TimelockRequest) public timelockRequests;
    uint256 public nextTimelockId = 1;
    uint256 public constant TIMELOCK_DELAY = 2 days;
    
    function queueTimelock(
        address target,
        bytes calldata data,
        uint256 value
    ) external onlyRole(TREASURY_ROLE) returns (uint256) {
        uint256 id = nextTimelockId++;
        timelockRequests[id] = TimelockRequest({
            target: target,
            data: data,
            value: value,
            executeAfter: block.timestamp + TIMELOCK_DELAY,
            executed: false
        });
        return id;
    }
    
    function executeTimelock(uint256 id) external onlyRole(TREASURY_ROLE) {
        TimelockRequest storage req = timelockRequests[id];
        require(!req.executed, "Already executed");
        require(block.timestamp >= req.executeAfter, "Timelock not expired");
        
        req.executed = true;
        (bool success,) = req.target.call{value: req.value}(req.data);
        require(success, "Execution failed");
    }
    
    // 7. 闪电贷防护
    modifier deferCheck() {
        _;
        _afterFunctionCheck();
    }
    
    function _afterFunctionCheck() internal view {
        // 检查关键状态不变量
        // 例如: 价格必须在合理范围内
        // 防止闪电贷操纵价格
        require(_checkInvariant(), "Invariant violated");
    }
    
    function _checkInvariant() internal view returns (bool) {
        // 实现状态不变量检查
        return true;
    }
}
```

### 8.10 工具链升级 (2026版)

| 工具 | 版本 | 用途 | 2026 新特性 |
|------|------|------|-------------|
| Foundry | v1.0 | EVM开发框架 | 并行测试/模糊测试增强 |
| Hardhat | v3.0 | EVM开发框架 | TypeScript原生支持 |
| Anchor | v0.30 | Solana开发 | IDL v3/TypeScript增强 |
| Scarb | v2.6 | Cairo开发 | Sierra IR优化 |
| viem | v2.0 | 前端以太坊交互 | EIP-5792批量调用 |
| wagmi | v2.0 | React以太坊Hooks | 多链原生支持 |
| RainbowKit | v2.0 | 钱包连接UI | 账户抽象原生支持 |
| Slither | v0.10 | 静态分析 | AI辅助漏洞检测 |
| Echidna | v3.0 | 属性测试 | 并行执行 |
| Certora Prover | v4.0 | 形式化验证 | 自动规则生成 |
| Tenderly | - | 监控模拟 | 实时MEV检测 |
| Defender | v2.0 | 安全运营 | 自动应急响应 |