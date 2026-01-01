from typing import Any

class UIContext:
    @staticmethod
    def activeContext() -> Any: ...  # noqa: N802

class AddressField:
    def __init__(self, *args: Any, **kwargs: Any) -> None: ...

class ChoiceField:
    def __init__(self, *args: Any, **kwargs: Any) -> None: ...

class SaveFileNameField:
    def __init__(self, *args: Any, **kwargs: Any) -> None: ...
    result: str

class OpenFileNameField:
    def __init__(self, *args: Any, **kwargs: Any) -> None: ...
    result: str

def get_form_input(*args: Any, **kwargs: Any) -> bool: ...
