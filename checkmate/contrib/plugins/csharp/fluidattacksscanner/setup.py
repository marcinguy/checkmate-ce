from .analyzer import FluidAttacksAnalyzer
from .issues_data import issues_data

analyzers = {
    'fluidattackscsharp':
        {
            'name': 'fluidattackscsharp',
            'title': 'fluidattackscsharp',
            'class': FluidAttacksAnalyzer,
            'language': 'csharp',
            'issues_data': issues_data,
        },
}
