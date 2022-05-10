from .analyzer import GosecAnalyzer
from .issues_data import issues_data

analyzers = {
    'gosec':
        {
            'name': 'gosec',
            'title': 'gosec',
            'class': GosecAnalyzer,
            'language': 'all',
            'issues_data': issues_data,
        },
}
