from .analyzer import GPTAnalyzer
from .issues_data import issues_data

analyzers = {
    'ptpt':
        {
            'name': 'ptpt',
            'title': 'ptpt',
            'class': GPTAnalyzer,
            'language': 'all',
            'issues_data': issues_data,
        },
}
