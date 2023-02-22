from .analyzer import FluidAttacksAnalyzer
from .issues_data import issues_data

analyzers = {
    'fluidattacks':
        {
            'name': 'fluidattacks',
            'title': 'fluidattacks',
            'class': FluidAttacksAnalyzer,
            'language': 'java',
            'issues_data': issues_data,
        },
}