from typing import Any

class Symbol:
    type: Any
    addr: int
    name: str

    def __init__(self, symbol_type: Any, addr: int, name: str) -> None: ...

class Type:
    @staticmethod
    def array(element_type: Type, count: int) -> Type: ...
    @staticmethod
    def int(width: int, sign: bool = True, altname: str = "") -> Type: ...
    @staticmethod
    def structure_type(builder: object) -> Type: ...

class StructureType:
    def __init__(self, width: int = 0, members: list[object] | None = None) -> None: ...
    width: int
    members: list[object]

class StructureBuilder:
    members: list[tuple[int, object, str]]

    @classmethod
    def create(cls) -> StructureBuilder: ...
    def insert(self, offset: int, typ: object, name: str) -> None: ...
