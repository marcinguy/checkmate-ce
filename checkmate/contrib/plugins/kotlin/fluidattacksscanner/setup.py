from .analyzer import FluidAttacksAnalyzer
from .issues_data import issues_data

analyzers = {
    'fluidattacksscannerkotlin':
        {
            'name': 'fluidattacksscannerkotlin',
            'title': 'fluidattacksscannerkotlin',
            'class': FluidAttacksAnalyzer,
            'language': 'kotlin',
            'issues_data': issues_data,
        },
}
