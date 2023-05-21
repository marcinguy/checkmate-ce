from .analyzer import PrivateGptAnalyzer
from .issues_data import issues_data

analyzers = {
    'privategptanalyzer':
        {
            'name': 'privategptanalyzer',
            'title': 'privategptanalyzer',
            'class': PrivateGptAnalyzer,
            'language': 'all',
            'issues_data': issues_data,
        },
}
