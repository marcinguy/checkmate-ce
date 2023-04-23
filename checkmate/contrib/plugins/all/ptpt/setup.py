from .analyzer import GptAnalyzer
from .issues_data import issues_data

analyzers = {
    'ptpt':
        {
            'name': 'ptpt',
            'title': 'ptpt',
            'class': GptAnalyzer,
            'language': 'all',
            'issues_data': issues_data,
        },
}
