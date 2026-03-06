from abc import ABC, abstractmethod

class BaseParser(ABC):
    @abstractmethod
    def parse(self, raw: str) -> dict | None:
        pass