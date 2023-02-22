from .analyzer import SemgrepeslintAnalyzer
from .issues_data import issues_data

analyzers = {
    'semgrepeslint':
        {
            'name': 'semgrepeslint',
            'title': 'semgrepeslint',
            'class': SemgrepeslintAnalyzer,
            'language': 'javascript',
            'issues_data': issues_data,
        },
}
