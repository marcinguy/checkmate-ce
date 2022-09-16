from .analyzer import PmdapexAnalyzer
from .issues_data import issues_data

analyzers = {
    'pmdapex':
        {
            'name': 'pmdapex',
            'title': 'PMDapex',
            'class': PmdapexAnalyzer,
            'language': 'all',
            'issues_data': issues_data,
        },
}
