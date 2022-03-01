# -*- coding: utf-8 -*-


from collections import defaultdict
import abc


class MapReducer(object, metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def map(self, items):
        return []

    @abc.abstractmethod
    def reduce(self, key, values):
        return []

    def filter(self, items):
        return items

    def mapreduce(self, items):
        map_results = [item for sublist in [self.map(item)
                       for item in self.filter(items)]
                       for item in sublist if item]
        grouped_results = defaultdict(lambda: [])
        for key, value in map_results:
            grouped_results[key].append(value)
        return dict([(key, self.reduce(key, values))
                     for key, values in list(grouped_results.items())])
