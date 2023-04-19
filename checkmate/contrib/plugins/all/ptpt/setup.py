from .analyzer import GPTAnalyzer
from .issues_data import issues_data

analyzers = {
    'gpt':
        {
            'name': 'gpt',
            'title': 'gpt',
            'class': GPTAnalyzer,
            'language': 'all',
            'issues_data': issues_data,
        },
}
