from .analyzer import TfsecAnalyzer
from .issues_data import issues_data

analyzers = {
    'checkov':
        {
            'name': 'tfsec',
            'title': 'tfsec',
            'class': TfsecAnalyzer,
            'language': 'iac',
            'issues_data': issues_data,
        },
}
