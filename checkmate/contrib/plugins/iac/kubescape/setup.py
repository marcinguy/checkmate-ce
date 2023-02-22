from .analyzer import KubescapeAnalyzer
from .issues_data import issues_data

analyzers = {
    'kubescape':
        {
            'name': 'kubescape',
            'title': 'kubescape',
            'class': KubescapeAnalyzer,
            'language': 'iac',
            'issues_data': issues_data,
        },
}

