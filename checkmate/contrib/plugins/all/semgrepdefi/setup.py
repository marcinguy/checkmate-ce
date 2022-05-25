from .analyzer import SemgrepDeFiAnalyzer
from .issues_data import issues_data

analyzers = {
    'semgrepdefi':
        {
            'name': 'semgrepdefi',
            'title': 'semgrepdefi',
            'class': SemgrepDeFiAnalyzer,
            'language': 'all',
            'issues_data': issues_data,
        },
}
