from .analyzer import ConfusedAnalyzer
from .issues_data import issues_data

analyzers = {
    'confused':
        {
            'title': 'Confused',
            'class': ConfusedAnalyzer,
            'language': 'supply',
            'issues_data': issues_data,
        },
}
