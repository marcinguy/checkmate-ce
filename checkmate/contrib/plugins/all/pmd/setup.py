from .analyzer import PmdAnalyzer
from .issues_data import issues_data

analyzers = {
    'pmd':
        {
            'name': 'pmd',
            'title': 'PMD',
            'class': PmdAnalyzer,
            'language': 'all',
            'issues_data': issues_data,
        },
}
