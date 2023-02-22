from .analyzer import PmdapexAnalyzer
from .issues_data import issues_data

analyzers = {
    'pmdapex':
        {
            'name': 'pmdapex',
            'title': 'PMDapex',
            'class': PmdapexAnalyzer,
            'language': 'apex',
            'issues_data': issues_data,
        },
}
