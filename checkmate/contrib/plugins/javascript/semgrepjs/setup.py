from .analyzer import SemgrepJsAnalyzer
from .issues_data import issues_data

analyzers = {
    'semgrepjs':
        {
            'name': 'semgrepjs',
            'title': 'semgrepjs',
            'class': SemgrepJsAnalyzer,
            'language': 'javascript',
            'issues_data': issues_data,
        },
}
