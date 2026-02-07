import { VulnerabilityPattern } from '../types';

/**
 * Batch 50: Advanced DeFi Attack Vectors
 * SOL7276-SOL7325 (50 patterns)
 * Focus: MEV, sandwich attacks, liquidity manipulation, governance exploits
 */
export const advancedDefiPatterns: VulnerabilityPattern[] = [
  // MEV Protection Patterns
  {
    id: 'SOL7276',
    name: 'Missing MEV Protection',
    description: 'DEX swap without slippage or deadline protection enables sandwich attacks',
    severity: 'critical',
    category: 'defi',
    pattern: /swap.*amount.*min.*0|swap(?!.*deadline)|exchange(?!.*slippage)/gi,
    recommendation: 'Implement minimum output amount and deadline parameters for all swaps'
  },
  {
    id: 'SOL7277',
    name: 'Frontrunnable Transaction',
    description: 'Transaction reveals profitable opportunity before execution',
    severity: 'high',
    category: 'defi',
    pattern: /price.*update|oracle.*set|rate.*change/gi,
    recommendation: 'Use commit-reveal scheme or private mempools for sensitive transactions'
  },
  {
    id: 'SOL7278',
    name: 'Missing Sandwich Protection',
    description: 'No protection against sandwich attacks in swap function',
    severity: 'critical',
    category: 'defi',
    pattern: /swap.*\{[^}]*\}(?!.*assert.*price)/gi,
    recommendation: 'Check price impact and revert if slippage exceeds threshold'
  },
  {
    id: 'SOL7279',
    name: 'JIT Liquidity Vulnerability',
    description: 'Protocol vulnerable to just-in-time liquidity attacks',
    severity: 'high',
    category: 'defi',
    pattern: /add_liquidity.*remove_liquidity|mint.*burn/gi,
    recommendation: 'Implement liquidity lock periods and anti-JIT measures'
  },
  {
    id: 'SOL7280',
    name: 'Backrunnable Oracle Update',
    description: 'Oracle update can be backrun for profit extraction',
    severity: 'high',
    category: 'defi',
    pattern: /update_price|set_oracle|push_price/gi,
    recommendation: 'Use time-weighted oracles and commit-reveal for updates'
  },
  
  // Liquidity Manipulation
  {
    id: 'SOL7281',
    name: 'Thin Liquidity Exploitation',
    description: 'Pool vulnerable to price manipulation via low liquidity',
    severity: 'high',
    category: 'defi',
    pattern: /reserve.*<|liquidity.*threshold/gi,
    recommendation: 'Implement minimum liquidity requirements and circuit breakers'
  },
  {
    id: 'SOL7282',
    name: 'LP Token Price Manipulation',
    description: 'LP token pricing vulnerable to flash loan attacks',
    severity: 'critical',
    category: 'defi',
    pattern: /lp.*price|pool.*share.*value/gi,
    recommendation: 'Use time-weighted LP pricing and spot price checks'
  },
  {
    id: 'SOL7283',
    name: 'Virtual Reserve Attack',
    description: 'Virtual reserve calculation exploitable for profit extraction',
    severity: 'high',
    category: 'defi',
    pattern: /virtual.*reserve|synthetic.*balance/gi,
    recommendation: 'Bound virtual reserves to actual token balances'
  },
  {
    id: 'SOL7284',
    name: 'Concentrated Liquidity Exploit',
    description: 'Concentrated liquidity position vulnerable to price manipulation',
    severity: 'high',
    category: 'defi',
    pattern: /tick.*range|position.*bounds|concentrated/gi,
    recommendation: 'Implement tick manipulation protection and position limits'
  },
  {
    id: 'SOL7285',
    name: 'Imbalanced Pool Attack',
    description: 'Protocol allows excessive pool imbalance for arbitrage',
    severity: 'medium',
    category: 'defi',
    pattern: /imbalance|skew.*ratio|weight.*deviation/gi,
    recommendation: 'Implement maximum imbalance ratios and rebalancing mechanisms'
  },

  // Governance Attacks
  {
    id: 'SOL7286',
    name: 'Flash Loan Governance Attack',
    description: 'Governance voting vulnerable to flash loan manipulation',
    severity: 'critical',
    category: 'governance',
    pattern: /vote.*power|governance.*token|proposal.*execute/gi,
    recommendation: 'Implement voting escrow and snapshot-based voting power'
  },
  {
    id: 'SOL7287',
    name: 'Proposal Frontrunning',
    description: 'Governance proposal can be frontrun before execution',
    severity: 'high',
    category: 'governance',
    pattern: /queue.*proposal|execute.*delay/gi,
    recommendation: 'Use commit-reveal for proposals and randomized execution windows'
  },
  {
    id: 'SOL7288',
    name: 'Bribery Vulnerability',
    description: 'Governance system vulnerable to vote buying attacks',
    severity: 'high',
    category: 'governance',
    pattern: /delegate.*vote|voting.*delegation/gi,
    recommendation: 'Implement private voting and anti-bribery mechanisms'
  },
  {
    id: 'SOL7289',
    name: 'Timelock Bypass',
    description: 'Governance timelock can be circumvented',
    severity: 'critical',
    category: 'governance',
    pattern: /timelock.*skip|delay.*override|emergency.*execute/gi,
    recommendation: 'Ensure all governance actions go through mandatory timelock'
  },
  {
    id: 'SOL7290',
    name: 'Quorum Manipulation',
    description: 'Governance quorum can be gamed through token manipulation',
    severity: 'high',
    category: 'governance',
    pattern: /quorum.*check|minimum.*votes|threshold.*met/gi,
    recommendation: 'Use time-weighted quorum calculations and snapshot voting'
  },

  // Lending Protocol Attacks
  {
    id: 'SOL7291',
    name: 'Collateral Factor Manipulation',
    description: 'Collateral factor can be exploited for excess borrowing',
    severity: 'critical',
    category: 'defi',
    pattern: /collateral.*factor|ltv.*ratio|borrow.*limit/gi,
    recommendation: 'Implement conservative collateral factors with safety margins'
  },
  {
    id: 'SOL7292',
    name: 'Interest Rate Manipulation',
    description: 'Interest rate model vulnerable to utilization gaming',
    severity: 'high',
    category: 'defi',
    pattern: /utilization.*rate|interest.*model|borrow.*rate/gi,
    recommendation: 'Use time-weighted utilization and rate smoothing'
  },
  {
    id: 'SOL7293',
    name: 'Bad Debt Socialization',
    description: 'Protocol improperly socializes bad debt across lenders',
    severity: 'high',
    category: 'defi',
    pattern: /bad.*debt|shortfall|underwater.*position/gi,
    recommendation: 'Implement insurance fund and proper bad debt handling'
  },
  {
    id: 'SOL7294',
    name: 'Liquidation Cascade',
    description: 'Liquidation mechanism can trigger cascade failures',
    severity: 'critical',
    category: 'defi',
    pattern: /liquidate.*all|batch.*liquidation|mass.*close/gi,
    recommendation: 'Implement gradual liquidation and circuit breakers'
  },
  {
    id: 'SOL7295',
    name: 'Dust Attack on Lending',
    description: 'Small position dust can block liquidations',
    severity: 'medium',
    category: 'defi',
    pattern: /position.*size.*min|dust.*threshold/gi,
    recommendation: 'Implement minimum position sizes and dust collection'
  },

  // Perpetual/Derivatives Attacks
  {
    id: 'SOL7296',
    name: 'Funding Rate Manipulation',
    description: 'Perpetual funding rate exploitable through position manipulation',
    severity: 'high',
    category: 'defi',
    pattern: /funding.*rate|perpetual.*payment|mark.*index/gi,
    recommendation: 'Use bounded funding rates and manipulation-resistant calculations'
  },
  {
    id: 'SOL7297',
    name: 'Mark Price Deviation',
    description: 'Mark price can deviate significantly from index price',
    severity: 'high',
    category: 'defi',
    pattern: /mark.*price|fair.*price|index.*deviation/gi,
    recommendation: 'Implement mark price bounds and deviation circuit breakers'
  },
  {
    id: 'SOL7298',
    name: 'Insurance Fund Drainage',
    description: 'Insurance fund can be drained through coordinated attacks',
    severity: 'critical',
    category: 'defi',
    pattern: /insurance.*fund|deficit.*cover|socialized.*loss/gi,
    recommendation: 'Implement insurance fund protection and contribution caps'
  },
  {
    id: 'SOL7299',
    name: 'ADL Manipulation',
    description: 'Auto-deleveraging can be gamed for profit',
    severity: 'high',
    category: 'defi',
    pattern: /auto.*deleverage|adl.*trigger|position.*reduce/gi,
    recommendation: 'Use fair ADL ordering and manipulation-resistant triggers'
  },
  {
    id: 'SOL7300',
    name: 'Basis Trade Attack',
    description: 'Basis between spot and perpetual exploitable',
    severity: 'medium',
    category: 'defi',
    pattern: /basis.*trade|spot.*perp|cash.*carry/gi,
    recommendation: 'Implement basis bounds and arbitrage-resistant mechanisms'
  },

  // Staking Attacks
  {
    id: 'SOL7301',
    name: 'Stake Inflation Attack',
    description: 'Staking rewards dilutable through stake manipulation',
    severity: 'high',
    category: 'defi',
    pattern: /stake.*reward|emission.*rate|inflation.*schedule/gi,
    recommendation: 'Use time-weighted staking and vesting schedules'
  },
  {
    id: 'SOL7302',
    name: 'Unstake Queue Gaming',
    description: 'Unstaking queue can be gamed for priority exit',
    severity: 'medium',
    category: 'defi',
    pattern: /unstake.*queue|withdrawal.*delay|exit.*priority/gi,
    recommendation: 'Implement fair unstaking queues with randomization'
  },
  {
    id: 'SOL7303',
    name: 'Reward Sniping',
    description: 'Staking rewards can be sniped through just-in-time staking',
    severity: 'high',
    category: 'defi',
    pattern: /reward.*distribution|stake.*before.*reward/gi,
    recommendation: 'Implement reward smoothing and stake lock periods'
  },
  {
    id: 'SOL7304',
    name: 'Slashing Evasion',
    description: 'Validator can evade slashing through stake manipulation',
    severity: 'high',
    category: 'defi',
    pattern: /slash.*condition|penalty.*check|validator.*stake/gi,
    recommendation: 'Implement unbonding periods and slashing during unstake'
  },
  {
    id: 'SOL7305',
    name: 'Delegation Manipulation',
    description: 'Stake delegation vulnerable to manipulation attacks',
    severity: 'medium',
    category: 'defi',
    pattern: /delegate.*stake|delegation.*reward|validator.*selection/gi,
    recommendation: 'Implement delegation caps and anti-gaming mechanisms'
  },

  // Bridge Attacks
  {
    id: 'SOL7306',
    name: 'Bridge Signature Replay',
    description: 'Cross-chain message signature replayable on other chains',
    severity: 'critical',
    category: 'bridge',
    pattern: /bridge.*signature|cross.*chain.*verify|relay.*message/gi,
    recommendation: 'Include chain ID and nonce in all bridge signatures'
  },
  {
    id: 'SOL7307',
    name: 'Bridge Oracle Manipulation',
    description: 'Bridge relies on manipulable oracle for price feeds',
    severity: 'critical',
    category: 'bridge',
    pattern: /bridge.*oracle|cross.*chain.*price|foreign.*rate/gi,
    recommendation: 'Use multiple oracle sources and manipulation detection'
  },
  {
    id: 'SOL7308',
    name: 'Wrapped Token Depegging',
    description: 'Wrapped token can depeg from underlying through bridge exploit',
    severity: 'critical',
    category: 'bridge',
    pattern: /wrapped.*token|bridge.*mint|peg.*ratio/gi,
    recommendation: 'Implement strict 1:1 backing and reserve proofs'
  },
  {
    id: 'SOL7309',
    name: 'Bridge Finality Attack',
    description: 'Bridge accepts transactions before finality',
    severity: 'critical',
    category: 'bridge',
    pattern: /confirmation.*count|finality.*check|block.*depth/gi,
    recommendation: 'Wait for sufficient confirmations before crediting'
  },
  {
    id: 'SOL7310',
    name: 'Message Ordering Attack',
    description: 'Cross-chain message ordering can be manipulated',
    severity: 'high',
    category: 'bridge',
    pattern: /message.*sequence|order.*nonce|relay.*order/gi,
    recommendation: 'Implement strict message ordering with sequence numbers'
  },

  // NFT/Gaming Attacks
  {
    id: 'SOL7311',
    name: 'Randomness Prediction',
    description: 'Game randomness predictable from on-chain data',
    severity: 'critical',
    category: 'nft',
    pattern: /random.*seed|entropy.*source|rng.*generate/gi,
    recommendation: 'Use VRF or commit-reveal for unpredictable randomness'
  },
  {
    id: 'SOL7312',
    name: 'NFT Reveal Frontrunning',
    description: 'NFT reveal process can be frontrun for rare selection',
    severity: 'high',
    category: 'nft',
    pattern: /reveal.*nft|metadata.*update|trait.*assign/gi,
    recommendation: 'Use commit-reveal pattern with delayed metadata'
  },
  {
    id: 'SOL7313',
    name: 'Royalty Bypass',
    description: 'NFT royalties can be bypassed through wrapper contracts',
    severity: 'medium',
    category: 'nft',
    pattern: /royalty.*fee|creator.*share|secondary.*sale/gi,
    recommendation: 'Use enforced royalty standards like pNFTs'
  },
  {
    id: 'SOL7314',
    name: 'Mint Sniping',
    description: 'NFT mint can be sniped by bots for rare tokens',
    severity: 'medium',
    category: 'nft',
    pattern: /mint.*public|open.*mint|first.*come/gi,
    recommendation: 'Implement allowlists and delayed reveal mechanisms'
  },
  {
    id: 'SOL7315',
    name: 'Game Economy Exploit',
    description: 'In-game economy vulnerable to item duplication or inflation',
    severity: 'high',
    category: 'nft',
    pattern: /game.*item|in.*game.*currency|craft.*duplicate/gi,
    recommendation: 'Implement strict item accounting and economic sinks'
  },

  // Advanced Token Attacks
  {
    id: 'SOL7316',
    name: 'Token Approval Hijack',
    description: 'Token approval can be hijacked through frontrunning',
    severity: 'high',
    category: 'token',
    pattern: /approve.*amount|allowance.*set|delegation.*grant/gi,
    recommendation: 'Use increaseAllowance/decreaseAllowance patterns'
  },
  {
    id: 'SOL7317',
    name: 'Rebasing Token Exploit',
    description: 'Rebasing token balance change exploitable in DeFi protocols',
    severity: 'high',
    category: 'token',
    pattern: /rebase.*token|elastic.*supply|balance.*adjust/gi,
    recommendation: 'Use shares-based accounting for rebasing tokens'
  },
  {
    id: 'SOL7318',
    name: 'Fee-on-Transfer Issues',
    description: 'Protocol doesnt handle fee-on-transfer tokens correctly',
    severity: 'high',
    category: 'token',
    pattern: /transfer.*fee|tax.*token|deflationary/gi,
    recommendation: 'Check actual received amount after transfers'
  },
  {
    id: 'SOL7319',
    name: 'Pausable Token DoS',
    description: 'Pausable token can DoS protocols during pause',
    severity: 'medium',
    category: 'token',
    pattern: /pausable|pause.*transfer|freeze.*token/gi,
    recommendation: 'Handle pause states gracefully in protocol logic'
  },
  {
    id: 'SOL7320',
    name: 'Token Migration Attack',
    description: 'Token migration process vulnerable to exploitation',
    severity: 'high',
    category: 'token',
    pattern: /token.*migration|upgrade.*token|swap.*old.*new/gi,
    recommendation: 'Implement secure migration with proper accounting'
  },

  // Protocol Composability Attacks
  {
    id: 'SOL7321',
    name: 'Read-Only Reentrancy',
    description: 'View function state exploitable during callback',
    severity: 'high',
    category: 'composability',
    pattern: /get.*price.*cpi|view.*after.*invoke|read.*during.*callback/gi,
    recommendation: 'Use reentrancy guards even for read operations'
  },
  {
    id: 'SOL7322',
    name: 'Cross-Protocol Arbitrage',
    description: 'Protocol state exploitable through multi-protocol interactions',
    severity: 'medium',
    category: 'composability',
    pattern: /multi.*protocol|cross.*integration|compose.*call/gi,
    recommendation: 'Account for cross-protocol interactions in security model'
  },
  {
    id: 'SOL7323',
    name: 'Aggregator Routing Exploit',
    description: 'DEX aggregator routing manipulable for profit extraction',
    severity: 'high',
    category: 'composability',
    pattern: /route.*optimize|path.*finding|aggregat.*swap/gi,
    recommendation: 'Implement route validation and slippage protection'
  },
  {
    id: 'SOL7324',
    name: 'Vault Strategy Manipulation',
    description: 'Yield vault strategy exploitable through deposit/withdraw timing',
    severity: 'high',
    category: 'composability',
    pattern: /vault.*strategy|yield.*optimize|harvest.*profit/gi,
    recommendation: 'Implement deposit fees and withdrawal delays'
  },
  {
    id: 'SOL7325',
    name: 'Composability Dependency Risk',
    description: 'Protocol has unmitigated dependency on external protocols',
    severity: 'medium',
    category: 'composability',
    pattern: /external.*protocol|third.*party.*integration|dependency.*check/gi,
    recommendation: 'Implement fallbacks and dependency health checks'
  }
];

export default advancedDefiPatterns;
