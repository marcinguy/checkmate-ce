from .analyzer import FluidAttacksAnalyzer
from .issues_data import issues_data

analyzers = {
    'fluidattacksswift':
        {
            'name': 'fluidattacksswift',
            'title': 'fluidattacksswift',
            'class': FluidAttacksAnalyzer,
            'language': 'swift',
            'issues_data': issues_data,
        },
}
