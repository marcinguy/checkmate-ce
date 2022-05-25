# -*- coding: utf-8 -*-


issues_data = {

    "compound-borrowfresh-reentrancy": {
        "title": "compound borrowfresh reentrancy",
        "display_name": "Compound borrowfres reentrancy",
        "severity": "3",
        "categories": [
            "security"
        ],
        "description": "Function borrowFresh() in Compound performs state update after doTransferOut()"
    },
    "compound-sweeptoken-not-restricted": {
        "title": "compound sweeptoken not restricted",
        "display_name": "compound sweeptoken not restricted",
        "severity": "3",
        "categories": [
            "security"
        ],
        "description": "Function sweepToken is allowed to be called by anyone"
    },
    "erc20-public-transfer": {
        "title": "erc20 public transfer",
        "display_name": "erc20 public transfer",
        "severity": "3",
        "categories": [
            "security"
        ],
        "description": "Custom ERC20 implementation exposes _transfer() as public"
    },
    "erc20-public-burn": {
        "title": "erc20 public burn",
        "display_name": "erc20 public burn",
        "severity": "3",
        "categories": [
            "security"
        ],
        "description": "Anyone can burn tokens of other accounts"
    },
    "erc677-reentrancy": {
        "title": "erc677 reentrancy",
        "display_name": "erc677 reentrancy",
        "severity": "3",
        "categories": [
            "security"
        ],
        "description": "ERC677 callAfterTransfer() reentrancy"
    },
    "erc777-reentrancy": {
        "title": "erc777 reentrancy",
        "display_name": "erc777 reentrancy",
        "severity": "3",
        "categories": [
            "security"
        ],
        "description": "ERC777 tokensReceived() reentrancy"
    },
    "erc721-reentrancy": {
        "title": "erc721 reentrancy",
        "display_name": "erc721 reentrancy",
        "severity": "3",
        "categories": [
            "security"
        ],
        "description": "ERC721 onERC721Received() reentrancy"
    },
    "gearbox-tokens-path-confusion": {
        "title": "gearbox tokens path confusion",
        "display_name": "gearbox-tokens-path-confusion",
        "severity": "3",
        "categories": [
            "security"
        ],
        "description": "UniswapV3 adapter implemented incorrect extraction of path parameters"
    },
    "keeper-network-oracle-manipulation": {
        "title": "keeper network oracle manipulation",
        "display_name": "keeper network oracle manipulation",
        "severity": "3",
        "categories": [
            "security"
        ],
        "description": "Keep3rV2.current() call has high data freshness, but it has low security, an exploiter simply needs to manipulate 2 data points to be able to impact the feed."
    },
    "basic-oracle-manipulation": {
        "title": "basic oracle manipulation",
        "display_name": "basic oracle manipulation",
        "severity": "3",
        "categories": [
            "security"
        ],
        "description": "getSharePrice() can be manipulated via flashloan"
    },
    "redacted-cartel-custom-approval-bug": {
        "title": "redacted cartel custom approval bug",
        "display_name": "redacted cartel custom approval bug",
        "severity": "3",
        "categories": [
            "security"
        ],
        "description": "transferFrom() can steal allowance of other accounts"
    },
    "rigoblock-missing-access-control": {
        "title": "rigoblock missing access control",
        "display_name": "rigoblock missing access control",
        "severity": "3",
        "categories": [
            "security"
        ],
        "description": "setMultipleAllowances() is missing onlyOwner modifier"
    },
    "oracle-price-update-not-restricted": {
        "title": "oracle price update not restricted",
        "display_name": "oracle price update not restricted",
        "severity": "3",
        "categories": [
            "security"
        ],
        "description": "Oracle price data can be submitted by anyone"
    },
    "superfluid-ctx-injection": {
        "title": "superfluid ctx injection",
        "display_name": "superfluid ctx injection",
        "severity": "3",
        "categories": [
            "security"
        ],
        "description": "A specially crafted calldata may be used to impersonate other accounts"
    },
    "tecra-coin-burnfrom-bug": {
        "title": "tecra coin burnfrom bug",
        "display_name": "tecra coin burnfrom bug",
        "severity": "3",
        "categories": [
            "security"
        ],
        "description": "Parameter from is checked at incorrect position in _allowances mapping"
    }
}




