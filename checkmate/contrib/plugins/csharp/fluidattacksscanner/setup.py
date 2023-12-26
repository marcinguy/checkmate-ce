from .analyzer import FluidAttacksAnalyzer
from .issues_data import issues_data

analyzers = {
    'fluidattacksscannercsharp':
        {
            'name': 'fluidattacksscannercsharp',
            'title': 'fluidattacksscannercsharp',
            'class': FluidAttacksAnalyzer,
            'language': 'csharp',
            'issues_data': issues_data,
        },
}
