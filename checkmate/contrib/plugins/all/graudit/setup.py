from .analyzer import GrauditAnalyzer
from .issues_data import issues_data

analyzers = {
    'graudit':
        {
            'name': 'graudit',
            'title': 'graudit',
            'class': GrauditAnalyzer,
            'language': 'all',
            'issues_data': issues_data,
        },
}
