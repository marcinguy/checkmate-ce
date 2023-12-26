from .analyzer import FluidAttacksAnalyzer
from .issues_data import issues_data

analyzers = {
    'fluidattacksscannerpython':
        {
            'name': 'fluidattacksscannerpython',
            'title': 'fluidattacksscannerpython',
            'class': FluidAttacksAnalyzer,
            'language': 'python',
            'issues_data': issues_data,
        },
}
