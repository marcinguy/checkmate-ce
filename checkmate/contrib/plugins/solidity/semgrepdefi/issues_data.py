issues_data = {   'basic-oracle-manipulation': {   'categories': ['security'],
                                     'description': 'getSharePrice() can be '
                                                    'manipulated via flashloan',
                                     'display_name': 'basic oracle '
                                                     'manipulation',
                                     'file': '%(issue.file)s',
                                     'line': '%(issue.line)s',
                                     'severity': '3',
                                     'title': 'basic oracle manipulation'},
    'compound-borrowfresh-reentrancy': {   'categories': ['security'],
                                           'description': 'Function '
                                                          'borrowFresh() in '
                                                          'Compound performs '
                                                          'state update after '
                                                          'doTransferOut()',
                                           'display_name': 'Compound '
                                                           'borrowfres '
                                                           'reentrancy',
                                           'file': '%(issue.file)s',
                                           'line': '%(issue.line)s',
                                           'severity': '3',
                                           'title': 'compound borrowfresh '
                                                    'reentrancy'},
    'compound-sweeptoken-not-restricted': {   'categories': ['security'],
                                              'description': 'Function '
                                                             'sweepToken is '
                                                             'allowed to be '
                                                             'called by anyone',
                                              'display_name': 'compound '
                                                              'sweeptoken not '
                                                              'restricted',
                                              'file': '%(issue.file)s',
                                              'line': '%(issue.line)s',
                                              'severity': '3',
                                              'title': 'compound sweeptoken '
                                                       'not restricted'},
    'erc20-public-burn': {   'categories': ['security'],
                             'description': 'Anyone can burn tokens of other '
                                            'accounts',
                             'display_name': 'erc20 public burn',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '3',
                             'title': 'erc20 public burn'},
    'erc20-public-transfer': {   'categories': ['security'],
                                 'description': 'Custom ERC20 implementation '
                                                'exposes _transfer() as public',
                                 'display_name': 'erc20 public transfer',
                                 'file': '%(issue.file)s',
                                 'line': '%(issue.line)s',
                                 'severity': '3',
                                 'title': 'erc20 public transfer'},
    'erc677-reentrancy': {   'categories': ['security'],
                             'description': 'ERC677 callAfterTransfer() '
                                            'reentrancy',
                             'display_name': 'erc677 reentrancy',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '3',
                             'title': 'erc677 reentrancy'},
    'erc721-reentrancy': {   'categories': ['security'],
                             'description': 'ERC721 onERC721Received() '
                                            'reentrancy',
                             'display_name': 'erc721 reentrancy',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '3',
                             'title': 'erc721 reentrancy'},
    'erc777-reentrancy': {   'categories': ['security'],
                             'description': 'ERC777 tokensReceived() '
                                            'reentrancy',
                             'display_name': 'erc777 reentrancy',
                             'file': '%(issue.file)s',
                             'line': '%(issue.line)s',
                             'severity': '3',
                             'title': 'erc777 reentrancy'},
    'gearbox-tokens-path-confusion': {   'categories': ['security'],
                                         'description': 'UniswapV3 adapter '
                                                        'implemented incorrect '
                                                        'extraction of path '
                                                        'parameters',
                                         'display_name': 'gearbox-tokens-path-confusion',
                                         'file': '%(issue.file)s',
                                         'line': '%(issue.line)s',
                                         'severity': '3',
                                         'title': 'gearbox tokens path '
                                                  'confusion'},
    'keeper-network-oracle-manipulation': {   'categories': ['security'],
                                              'description': 'Keep3rV2.current() '
                                                             'call has high '
                                                             'data freshness, '
                                                             'but it has low '
                                                             'security, an '
                                                             'exploiter simply '
                                                             'needs to '
                                                             'manipulate 2 '
                                                             'data points to '
                                                             'be able to '
                                                             'impact the feed.',
                                              'display_name': 'keeper network '
                                                              'oracle '
                                                              'manipulation',
                                              'file': '%(issue.file)s',
                                              'line': '%(issue.line)s',
                                              'severity': '3',
                                              'title': 'keeper network oracle '
                                                       'manipulation'},
    'oracle-price-update-not-restricted': {   'categories': ['security'],
                                              'description': 'Oracle price '
                                                             'data can be '
                                                             'submitted by '
                                                             'anyone',
                                              'display_name': 'oracle price '
                                                              'update not '
                                                              'restricted',
                                              'file': '%(issue.file)s',
                                              'line': '%(issue.line)s',
                                              'severity': '3',
                                              'title': 'oracle price update '
                                                       'not restricted'},
    'redacted-cartel-custom-approval-bug': {   'categories': ['security'],
                                               'description': 'transferFrom() '
                                                              'can steal '
                                                              'allowance of '
                                                              'other accounts',
                                               'display_name': 'redacted '
                                                               'cartel custom '
                                                               'approval bug',
                                               'file': '%(issue.file)s',
                                               'line': '%(issue.line)s',
                                               'severity': '3',
                                               'title': 'redacted cartel '
                                                        'custom approval bug'},
    'rigoblock-missing-access-control': {   'categories': ['security'],
                                            'description': 'setMultipleAllowances() '
                                                           'is missing '
                                                           'onlyOwner modifier',
                                            'display_name': 'rigoblock missing '
                                                            'access control',
                                            'file': '%(issue.file)s',
                                            'line': '%(issue.line)s',
                                            'severity': '3',
                                            'title': 'rigoblock missing access '
                                                     'control'},
    'superfluid-ctx-injection': {   'categories': ['security'],
                                    'description': 'A specially crafted '
                                                   'calldata may be used to '
                                                   'impersonate other accounts',
                                    'display_name': 'superfluid ctx injection',
                                    'file': '%(issue.file)s',
                                    'line': '%(issue.line)s',
                                    'severity': '3',
                                    'title': 'superfluid ctx injection'},
    'tecra-coin-burnfrom-bug': {   'categories': ['security'],
                                   'description': 'Parameter from is checked '
                                                  'at incorrect position in '
                                                  '_allowances mapping',
                                   'display_name': 'tecra coin burnfrom bug',
                                   'file': '%(issue.file)s',
                                   'line': '%(issue.line)s',
                                   'severity': '3',
                                   'title': 'tecra coin burnfrom bug'}}
