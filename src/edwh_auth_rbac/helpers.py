def IS_IN_LIST(allowed_values):
    """
    Validates whether a given value is within a predefined list of allowed values.

    This function is a higher-order function that returns a validation function.
    The returned function checks if its input value is one of the allowed values.
    If the value is not in the allowed values, it returns the value along with
    an error message indicating the issue. Otherwise, it returns the value and None.

    Parameters
    ----------
    allowed_values : List
        A list of values that are considered valid.

    Returns
    -------
    Callable[[Any, Any], Tuple[Any, Optional[str]]]
        A function that validates its input value against the allowed values.

    Raises
    ------
    None
    """

    def execute(value, row):
        if value not in allowed_values:
            return value, f"{value} is not one of {allowed_values!r}"
        else:
            return value, None

    return execute
