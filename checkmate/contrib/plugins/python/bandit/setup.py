from .analyzer import BanditAnalyzer
from .issues_data import issues_data

analyzers = {
    'bandit':
        {
            'name': 'bandit',
            'title': 'Bandit',
            'class': BanditAnalyzer,
            'language': 'python',
            'issues_data': issues_data,
        },
}
