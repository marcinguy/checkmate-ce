from .analyzer import YaraAnalyzer
from .issues_data import issues_data

analyzers = {
    'yara':
        {
            'name': 'yara',
            'title': 'yara',
            'class': YaraAnalyzer,
            'language': 'all',
            'issues_data': issues_data,
        },
}
