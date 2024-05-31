def IS_IN_LIST(allowed_values):
    def execute(value, row):
        if value not in allowed_values:
            return value, f"{value} is not one of {allowed_values!r}"
        else:
            return value, None

    return execute
