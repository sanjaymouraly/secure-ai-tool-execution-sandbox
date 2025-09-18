"""A tiny sample module used by the demonstration workflows."""


def greet(name: str = "world") -> str:
    """Return a friendly greeting."""
    return f"Hello, {name}!"


def summarise(values: list[int]) -> dict[str, float]:
    """Return simple statistics for a list of numbers."""
    if not values:
        return {"count": 0, "sum": 0.0, "mean": 0.0, "min": 0, "max": 0}
    return {
        "count": len(values),
        "sum": float(sum(values)),
        "mean": sum(values) / len(values),
        "min": min(values),
        "max": max(values),
    }


if __name__ == "__main__":
    print(greet())
    print(summarise([3, 1, 4, 1, 5, 9, 2, 6]))
