from .analyzer import Text4shellAnalyzer
from .issues_data import issues_data

analyzers = {
    'text4shell':
        {
            'name': 'text4shell',
            'title': 'text4shell',
            'class': Text4shellAnalyzer,
            'language': 'cve',
            'issues_data': issues_data,
        },
}
