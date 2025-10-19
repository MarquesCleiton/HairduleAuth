from abc import ABC, abstractmethod

class BaseStrategy(ABC):
    @abstractmethod
    def execute(self, event):
        pass
