def IS_IN_LIST(allowed_values):
    def execute(value, row):
        # print('{} in {} ?'.format(value, allowed_values))
        if value not in allowed_values:
            return value, '{} is not one of {}'.format(value, repr(allowed_values))
        else:
            return value, None

    return execute
