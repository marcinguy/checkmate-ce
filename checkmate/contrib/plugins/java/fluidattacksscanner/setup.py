from .analyzer import FluidAttacksAnalyzer
from .issues_data import issues_data

analyzers = {
    'fluidattacksscannerjava':
        {
            'name': 'fluidattacksscannerjava',
            'title': 'fluidattacksscannerjava',
            'class': FluidAttacksAnalyzer,
            'language': 'java',
            'issues_data': issues_data,
        },
}
